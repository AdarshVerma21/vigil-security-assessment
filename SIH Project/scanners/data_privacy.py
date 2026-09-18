"""Opt-in passive data-storage and privacy checks."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import parse_qsl, urlsplit

import requests

from core.base import Scanner


class DataPrivacyScanner(Scanner):
    """Detect sensitive data exposed in passive HTTP and browser surfaces."""

    name = "data-privacy"
    _patterns = (
        ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
        ("phone", re.compile(r"(?<!\d)(?:\+?\d[\d .()-]{8,}\d)(?!\d)")),
        ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
        ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
        ("api_key", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{8,}")),
        ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")),
    )
    _sensitive_query_keys = re.compile(
        r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|auth|ssn|"
        r"credit[_-]?card|email|phone|address)"
    )

    def scan(self) -> List[Any]:
        settings = self.config.get("data_privacy", {})
        if not isinstance(settings, dict) or not settings.get("enabled", False):
            return self.findings
        paths = self._paths(settings)
        for path in paths:
            self._check_url(path, settings)
            response = self._get(path)
            if response is not None:
                self._check_response(path, response, settings)
        self._check_browser_storage(settings)
        return self.findings

    def _paths(self, settings: Dict[str, Any]) -> List[str]:
        configured = settings.get("paths", [])
        paths = [path for path in configured if isinstance(path, str) and path.startswith("/")] if isinstance(configured, list) else []
        if settings.get("discover", True):
            try:
                from scanners.dast import DastScanner

                discovery = DastScanner(self.target_url, self.config)
                root = discovery.request("GET", "/")
                paths.extend(discovery.discover_endpoints(root))
            except (requests.RequestException, ValueError):
                pass
        result: List[str] = []
        for path in paths:
            if path not in result:
                result.append(path)
        return result[: max(1, min(int(settings.get("max_paths", 25)), 100))]

    def _get(self, path: str) -> requests.Response | None:
        try:
            return self.request("GET", path)
        except (requests.RequestException, ValueError):
            return None

    def _check_url(self, path: str, settings: Dict[str, Any]) -> None:
        query = parse_qsl(urlsplit(path).query, keep_blank_values=True)
        for key, value in query:
            if not self._sensitive_query_keys.search(key) and not self._find_match(value):
                continue
            data_type, sample = self._find_match(value) or ("sensitive_query_key", value)
            self._finding(
                "Medium",
                f"Sensitive data appears in a URL query string: {path}.",
                {"location": "url_query", "parameter": key, "data_type": data_type,
                 "redacted_sample": self._redact(sample)},
                "Avoid placing secrets or personal data in URLs; use protected request bodies or headers and review proxy/log retention.",
            )

    def _check_response(
        self, path: str, response: requests.Response, settings: Dict[str, Any]
    ) -> None:
        body = response.text[: int(settings.get("max_response_bytes", 10000))]
        seen = set()
        for data_type, pattern in self._patterns:
            match = pattern.search(body)
            if not match or data_type in seen:
                continue
            seen.add(data_type)
            self._finding(
                "Medium" if data_type in {"email", "phone"} else "High",
                f"Sensitive {data_type.replace('_', ' ')} data appears in an API or page response.",
                {"location": "http_response", "path": path, "status": response.status_code,
                 "data_type": data_type, "redacted_sample": self._redact(match.group(0))},
                "Minimize response fields, redact sensitive values, and enforce least-privilege data access.",
            )

        for key, value in response.headers.items():
            if self._sensitive_query_keys.search(key):
                self._finding(
                    "High",
                    f"Sensitive header data is exposed in the response from {path}.",
                    {"location": "response_header", "header": key, "redacted_sample": "[REDACTED]"},
                    "Do not return credentials or tokens in response headers unless strictly required.",
                )

    def _check_browser_storage(self, settings: Dict[str, Any]) -> None:
        if not settings.get("browser_storage", False):
            return
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            return
        paths = settings.get("browser_paths", ["/"])
        if not isinstance(paths, list):
            return
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, args=["--disable-gpu", "--no-sandbox"])
                try:
                    page = browser.new_page()
                    for path in paths:
                        if not isinstance(path, str) or not path.startswith("/"):
                            continue
                        page.goto(self._absolute(path), wait_until="domcontentloaded")
                        storage = page.evaluate(
                            """() => ({
                                local: Object.fromEntries(Object.entries(localStorage)),
                                session: Object.fromEntries(Object.entries(sessionStorage))
                            })"""
                        )
                        self._inspect_storage(path, storage, settings)
                finally:
                    browser.close()
        except (PlaywrightError, ValueError):
            return

    def _inspect_storage(self, path: str, storage: Any, settings: Dict[str, Any]) -> None:
        if not isinstance(storage, dict):
            return
        for location, values in storage.items():
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                text = f"{key}={value}"
                match = self._find_match(text)
                if not match and not self._sensitive_query_keys.search(str(key)):
                    continue
                data_type, sample = match or ("sensitive_storage_key", text)
                self._finding(
                    "High" if data_type not in {"email", "phone"} else "Medium",
                    f"Sensitive data appears in browser {location} storage.",
                    {"location": f"browser_{location}", "path": path, "key": str(key),
                     "data_type": data_type, "redacted_sample": self._redact(sample)},
                    "Keep secrets out of browser storage; prefer secure, short-lived, HttpOnly session mechanisms.",
                )

    def _finding(self, severity: str, description: str, evidence: Dict[str, Any], remediation: str) -> None:
        self.add_finding(
            f"PRIVACY-{len(self.findings) + 1:03d}", "PRIVACY", severity, description,
            json.dumps(evidence, sort_keys=True), remediation,
            "A02:2021 Cryptographic Failures" if severity == "High" else "A05:2021 Security Misconfiguration",
            cvss={"Medium": 6.5, "High": 8.2}.get(severity, 5.0),
            confidence="high",
        )

    @classmethod
    def _find_match(cls, value: str) -> tuple[str, str] | None:
        for data_type, pattern in cls._patterns:
            match = pattern.search(str(value))
            if match:
                return data_type, match.group(0)
        return None

    @staticmethod
    def _redact(value: str) -> str:
        value = str(value)
        if len(value) <= 8:
            return "[REDACTED]"
        return f"{value[:3]}...[REDACTED]...{value[-3:]}"

    def _absolute(self, path: str) -> str:
        return f"{self.target_url}/{path.lstrip('/')}"
