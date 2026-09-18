"""Opt-in, allowlist-bound authenticated role-boundary checks."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import requests

from core.base import Scanner
from core.models import Finding
from scanners.dast import DastScanner


class RbacScanner(Scanner):
    """Replay safe GET requests with dedicated accounts of different roles."""

    name = "rbac"

    def scan(self) -> List[Finding]:
        settings = self.config.get("rbac", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings
        endpoint_specs = self._endpoint_specs(settings)
        if not endpoint_specs:
            return self.findings
        levels = self._role_levels(settings.get("role_levels", {}))
        try:
            discovery = DastScanner(self.target_url, self.config)
            root = discovery.request("GET", "/")
            discovered = set(discovery.discover_endpoints(root))
        except requests.RequestException:
            return self.findings
        endpoint_specs = [
            spec
            for spec in endpoint_specs
            if spec["path"] in discovered and spec["required_role"] in levels
        ]
        accounts = settings.get("accounts", [])
        if not isinstance(accounts, list):
            return self.findings
        sessions: Dict[str, requests.Session] = {}
        for account in accounts:
            if isinstance(account, dict):
                session = self._login(account, settings.get("login", {}))
                if session is not None:
                    sessions[str(account.get("name", ""))] = session
        for spec in endpoint_specs:
            required_level = levels.get(spec["required_role"], 0)
            for account in accounts:
                if not isinstance(account, dict):
                    continue
                name = str(account.get("name", ""))
                actual_role = str(account.get("role", ""))
                if levels.get(actual_role, 0) >= required_level:
                    continue
                session = sessions.get(name)
                if name and actual_role in levels and session is not None:
                    self._check_access(session, account, spec, settings)
        return self.findings

    @staticmethod
    def _endpoint_specs(settings: Dict[str, Any]) -> List[Dict[str, str]]:
        configured = settings.get("endpoints", [])
        if not isinstance(configured, list):
            return []
        allowed: List[Dict[str, str]] = []
        for item in configured:
            if isinstance(item, str):
                allowed.append({"path": item, "required_role": "admin", "method": "GET"})
            elif isinstance(item, dict):
                path = item.get("path")
                role = item.get("required_role")
                method = str(item.get("method", "GET")).upper()
                if isinstance(path, str) and path.startswith("/") and isinstance(role, str) and method == "GET":
                    allowed.append({"path": path, "required_role": role, "method": method})
        return allowed

    @staticmethod
    def _role_levels(raw: Any) -> Dict[str, int]:
        if not isinstance(raw, dict):
            return {}
        levels: Dict[str, int] = {}
        for role, value in raw.items():
            try:
                levels[str(role)] = int(value)
            except (TypeError, ValueError):
                continue
        return levels

    def _login(self, account: Dict[str, Any], login: Any) -> requests.Session | None:
        if not isinstance(login, dict):
            return None
        username = account.get("username")
        password = account.get("password")
        login_path = login.get("path")
        if not all(isinstance(value, str) and value for value in (username, password, login_path)):
            return None
        if not login_path.startswith("/"):
            return None
        payload = {
            str(login.get("username_field", "username")): username,
            str(login.get("password_field", "password")): password,
        }
        session = requests.Session()
        session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
        try:
            response = self.request(
                str(login.get("method", "POST")).upper(),
                login_path,
                session=session,
                json=payload if login.get("format") == "json" else None,
                data=None if login.get("format") == "json" else payload,
            )
        except requests.RequestException:
            return None
        success_statuses = login.get("success_statuses", [200, 201, 204, 302])
        if not isinstance(success_statuses, list):
            success_statuses = [200, 201, 204, 302]
        return session if response.status_code in success_statuses else None

    def _check_access(
        self,
        session: requests.Session,
        account: Dict[str, Any],
        spec: Dict[str, str],
        settings: Dict[str, Any],
    ) -> None:
        try:
            response = self.request(spec["method"], spec["path"], session=session)
        except requests.RequestException:
            return
        max_bytes = int(settings.get("max_evidence_bytes", 500))
        body = response.text[:max_bytes]
        markers = settings.get("sensitive_markers", [])
        sensitive = isinstance(markers, list) and any(
            isinstance(marker, str) and marker.lower() in body.lower() for marker in markers
        )
        if 200 <= response.status_code < 300 or sensitive:
            self.add_finding(
                f"RBAC-{len(self.findings) + 1:03d}",
                "RBAC",
                "High",
                f"Lower-privileged role may access a higher-privileged endpoint: {spec['path']}.",
                self._evidence(response, account, spec, sensitive),
                "Enforce authorization server-side for every request and return 403 for insufficient privileges.",
                "A01:2021 Broken Access Control",
                cvss=8.1,
                confidence="high",
            )

    @staticmethod
    def _evidence(
        response: requests.Response,
        account: Dict[str, Any],
        spec: Dict[str, str],
        sensitive: bool,
    ) -> str:
        headers = {
            key: value
            for key, value in response.headers.items()
            if not any(
                marker in key.lower()
                for marker in ("authorization", "cookie", "token", "api-key", "secret")
            )
        }
        response_body = RbacScanner._redact(response.text[:500])
        return json.dumps(
            {
                "request": {
                    "method": spec["method"],
                    "path": spec["path"],
                    "role": account.get("role"),
                    "credentials": "[REDACTED]",
                },
                "response": {
                    "status": response.status_code,
                    "headers": headers,
                    "body_excerpt": response_body,
                    "sensitive_marker_matched": sensitive,
                },
            },
            sort_keys=True,
        )

    @staticmethod
    def _redact(value: str) -> str:
        """Remove common credential material from evidence excerpts."""
        value = re.sub(r"(?i)(authorization|cookie|password|token|secret)\s*[:=]\s*[^,\s}]+", r"\1=[REDACTED]", value)
        return re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "Bearer [REDACTED]", value)
