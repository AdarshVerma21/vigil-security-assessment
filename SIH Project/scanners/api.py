"""Opt-in, allowlist-bound API security checks."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

import requests

from core.base import Scanner
from scanners.dast import DastScanner


class ApiSecurityScanner(Scanner):
    """Check configured REST/GraphQL endpoints without destructive probes."""

    name = "api-security"
    _error_signatures = (
        r"traceback \(most recent call last\)",
        r"stack trace",
        r"exception in thread",
        r" at [\w.$]+\(.*:\d+\)",
        r"sql syntax.*mysql",
        r"node_modules/",
        r"/usr/(?:local/)?lib/",
        r"c:\\(?:users|windows)\\",
    )

    def scan(self) -> List[Any]:
        settings = self.config.get("api_security", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings
        endpoints = self._endpoints(settings)
        if not endpoints:
            return self.findings
        discovered = self._discover()
        accounts = self._accounts(settings)
        session = self._login(accounts[0], settings.get("login", {})) if accounts else None
        for endpoint in endpoints:
            if endpoint["path"] not in discovered:
                continue
            self._check_verbose_errors(endpoint, settings)
            if endpoint.get("requires_auth", True):
                self._check_missing_auth(endpoint, settings)
            if endpoint.get("mass_assignment"):
                self._check_mass_assignment(endpoint, session, settings)
        return self.findings

    def _discover(self) -> Dict[str, str]:
        discovery = DastScanner(self.target_url, self.config)
        root = discovery.request("GET", "/")
        paths = discovery.discover_endpoints(root)
        result: Dict[str, str] = {}
        for path in paths:
            lowered = path.lower()
            result[path] = "graphql" if "graphql" in lowered else (
                "rest" if lowered.startswith("/api/") or lowered == "/api" else "web"
            )
        return result

    @staticmethod
    def _endpoints(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = settings.get("endpoints", [])
        if not isinstance(raw, list):
            return []
        result = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            method = str(item.get("method", "GET")).upper()
            kind = item.get("type") or ("graphql" if "graphql" in str(path).lower() else "rest")
            if (
                isinstance(path, str)
                and path.startswith("/")
                and not urlsplit(path).netloc
                and method in {"GET", "POST", "PUT", "PATCH"}
                and kind in {"rest", "graphql"}
            ):
                result.append({
                    "path": path,
                    "method": method,
                    "type": kind,
                    "format": item.get("format", "json"),
                    "fields": item.get("fields", {}),
                    "requires_auth": bool(item.get("requires_auth", True)),
                    "mass_assignment": item.get("mass_assignment", False),
                    "unexpected_field": item.get("unexpected_field", "__vigil_probe"),
                    "verify_path": item.get("verify_path"),
                    "error_payload": item.get("error_payload"),
                })
        return result

    @staticmethod
    def _accounts(settings: Dict[str, Any]) -> List[Dict[str, str]]:
        raw = settings.get("accounts", [])
        if not isinstance(raw, list):
            return []
        result = []
        for item in raw:
            if isinstance(item, dict) and all(
                isinstance(item.get(key), str) and item[key]
                for key in ("name", "username", "password")
            ):
                result.append({key: item[key] for key in ("name", "username", "password")})
        return result

    def _login(self, account: Dict[str, str], login: Any) -> requests.Session | None:
        if not isinstance(login, dict) or not isinstance(login.get("path"), str):
            return None
        session = requests.Session()
        payload = {
            str(login.get("username_field", "username")): account["username"],
            str(login.get("password_field", "password")): account["password"],
        }
        try:
            response = self.request(
                str(login.get("method", "POST")).upper(),
                login["path"],
                session=session,
                json=payload if login.get("format") == "json" else None,
                data=None if login.get("format") == "json" else payload,
            )
        except (requests.RequestException, ValueError):
            return None
        statuses = login.get("success_statuses", [200, 201, 204, 302])
        return session if isinstance(statuses, list) and response.status_code in statuses else None

    def _check_missing_auth(self, endpoint: Dict[str, Any], settings: Dict[str, Any]) -> None:
        response = self._request_endpoint(endpoint, requests.Session(), settings)
        if response is None:
            return
        if 200 <= response.status_code < 300:
            self._finding(
                "High",
                f"API endpoint appears accessible without authentication: {endpoint['path']}.",
                {"endpoint": endpoint["path"], "type": endpoint["type"], "status": response.status_code},
                "Require authentication and enforce authorization on the server for this API route.",
            )

    def _check_verbose_errors(self, endpoint: Dict[str, Any], settings: Dict[str, Any]) -> None:
        payload = endpoint.get("error_payload")
        if not isinstance(payload, dict):
            payload = {"__vigil_invalid": {"unexpected": True}}
        response = self._request_endpoint(endpoint, requests.Session(), settings, payload)
        if response is None:
            return
        matched = next((sig for sig in self._error_signatures if re.search(sig, response.text, re.I)), None)
        if matched:
            self._finding(
                "Medium",
                f"API endpoint exposes verbose internal error details: {endpoint['path']}.",
                {"endpoint": endpoint["path"], "type": endpoint["type"], "status": response.status_code,
                 "matched_signature": matched, "response_excerpt": self._redact(response.text[:500])},
                "Return generic client-safe errors and log stack traces only on the server.",
            )

    def _check_mass_assignment(
        self, endpoint: Dict[str, Any], session: requests.Session | None, settings: Dict[str, Any]
    ) -> None:
        if session is None or not endpoint.get("verify_path"):
            return
        payload = dict(endpoint.get("fields", {})) if isinstance(endpoint.get("fields"), dict) else {}
        field = str(endpoint["unexpected_field"])
        canary = "vigil-mass-assignment-canary"
        payload[field] = canary
        response = self._request_endpoint(endpoint, session, settings, payload)
        if response is None or response.status_code >= 400:
            return
        verify_path = endpoint["verify_path"]
        if not isinstance(verify_path, str) or not verify_path.startswith("/"):
            return
        try:
            verified = self.request("GET", verify_path, session=session)
        except (requests.RequestException, ValueError):
            return
        if canary in verified.text:
            self._finding(
                "High",
                f"API accepted and persisted an unexpected field on {endpoint['path']}.",
                {"endpoint": endpoint["path"], "unexpected_field": field,
                 "verify_path": verify_path, "canary": canary},
                "Allowlist writable fields and reject or ignore client-controlled properties not in the API schema.",
            )

    def _request_endpoint(
        self, endpoint: Dict[str, Any], session: requests.Session, settings: Dict[str, Any],
        payload: Dict[str, Any] | None = None,
    ) -> requests.Response | None:
        body = payload if payload is not None else (
            endpoint.get("fields", {}) if isinstance(endpoint.get("fields"), dict) else {}
        )
        try:
            return self.request(
                endpoint["method"], endpoint["path"], session=session,
                json=body if endpoint["format"] == "json" else None,
                data=None if endpoint["format"] == "json" else body,
            )
        except (requests.RequestException, ValueError):
            return None

    def _finding(self, severity: str, description: str, evidence: Dict[str, Any], remediation: str) -> None:
        self.add_finding(
            f"API-{len(self.findings) + 1:03d}", "API", severity, description,
            json.dumps(evidence, sort_keys=True), remediation,
            "A01:2021 Broken Access Control" if "auth" in description.lower() or "persisted" in description.lower()
            else "A05:2021 Security Misconfiguration",
            cvss={"Medium": 6.5, "High": 8.1}.get(severity, 5.0),
            confidence="high",
        )

    @staticmethod
    def _redact(value: str) -> str:
        value = re.sub(r"(?i)(authorization|cookie|password|token|secret|api[-_]?key)\s*[:=]\s*[^,\s}]+", r"\1=[REDACTED]", value)
        return re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "******", value)
