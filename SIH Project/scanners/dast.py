"""Safe, passive dynamic application security checks."""

from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
import requests

from core.base import Scanner
from core.models import Finding


class DastScanner(Scanner):
    """Check a running target without mutation or exploit payloads."""

    name = "dast"
    _security_headers = {
        "Strict-Transport-Security": ("High", "A02:2021 Cryptographic Failures"),
        "Content-Security-Policy": ("Medium", "A05:2021 Security Misconfiguration"),
        "X-Frame-Options": ("Medium", "A05:2021 Security Misconfiguration"),
        "X-Content-Type-Options": ("Low", "A05:2021 Security Misconfiguration"),
        "Referrer-Policy": ("Low", "A05:2021 Security Misconfiguration"),
        "Permissions-Policy": ("Low", "A05:2021 Security Misconfiguration"),
    }

    def __init__(self, target_url: str, config: Dict[str, Any] | None = None):
        super().__init__(target_url, config)
        self.max_endpoints = int((config or {}).get("max_endpoints", 25))

    def scan(self) -> List[Finding]:
        try:
            response = self.request("GET", "/")
        except requests.RequestException as exc:
            self.add_finding(
                "DAST-001", "DAST", "High", "Target could not be reached.",
                f"{type(exc).__name__}: {exc}",
                "Confirm the authorized target is available and retry the assessment.",
                "A05:2021 Security Misconfiguration",
            )
            return self.findings

        self._check_headers(response)
        self._check_cookies(response)
        self.discover_endpoints(response)
        return self.findings

    def _check_headers(self, response: requests.Response) -> None:
        for header, (severity, owasp) in self._security_headers.items():
            if header == "Strict-Transport-Security" and urlsplit(response.url).scheme != "https":
                continue
            if not response.headers.get(header):
                self.add_finding(
                    f"DAST-{len(self.findings) + 2:03d}",
                    "DAST",
                    severity,
                    f"Missing security response header: {header}.",
                    f"{response.request.method} {response.url} returned without {header}.",
                    f"Configure {header} at the application or reverse-proxy layer.",
                    owasp,
                )

    def _check_cookies(self, response: requests.Response) -> None:
        for cookie in response.cookies:
            if not cookie.secure:
                self.add_finding(
                    "DAST-COOKIE-001", "DAST", "Medium",
                    "Session cookie is missing the Secure attribute.",
                    f"Cookie {cookie.name} was set without Secure.",
                    "Set Secure on all authentication and session cookies.",
                    "A05:2021 Security Misconfiguration",
                )
            if "HttpOnly" not in cookie._rest:
                self.add_finding(
                    "DAST-COOKIE-002", "DAST", "Medium",
                    "Session cookie is missing the HttpOnly attribute.",
                    f"Cookie {cookie.name} was set without HttpOnly.",
                    "Set HttpOnly on authentication and session cookies.",
                    "A05:2021 Security Misconfiguration",
                )

    def discover_endpoints(self, response: requests.Response) -> List[str]:
        """Return same-origin paths from config and the root HTML document."""
        soup = BeautifulSoup(response.text, "html.parser")
        origin = urlsplit(self.target_url).netloc
        endpoints: Set[str] = set(self.config.get("endpoints", []))
        for element in soup.find_all("a", href=True):
            endpoints.add(element.get("href", ""))
        for element in soup.find_all("form", action=True):
            endpoints.add(element.get("action", ""))
        discovered: List[str] = []
        for endpoint in sorted(endpoints)[: self.max_endpoints]:
            candidate = urljoin(self.target_url + "/", endpoint)
            if urlsplit(candidate).netloc != origin:
                continue
            path = urlsplit(candidate).path or "/"
            if urlsplit(candidate).query:
                path += f"?{urlsplit(candidate).query}"
            discovered.append(path)
            try:
                probe = self.request("HEAD", candidate)
            except requests.RequestException:
                continue
            if probe.status_code >= 500:
                self.add_finding(
                    "DAST-API-001", "DAST", "Medium",
                    "Discovered endpoint returned a server error to a safe HEAD request.",
                    f"{candidate} returned HTTP {probe.status_code}.",
                    "Review server logs and return controlled error responses.",
                    "A05:2021 Security Misconfiguration",
                )
        return discovered
