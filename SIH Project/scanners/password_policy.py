"""Opt-in password-policy and login-protection checks."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List

import requests

from core.base import Scanner


class PasswordPolicyScanner(Scanner):
    """Check explicitly configured password and login-policy endpoints."""

    name = "password-policy"
    _success_statuses = [200, 201, 202, 204, 302]

    def scan(self) -> List[Any]:
        settings = self.config.get("password_policy", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings

        policy = settings.get("rules", {})
        if not isinstance(policy, dict):
            return self.findings
        test_passwords = self._test_passwords(policy)
        accounts = self._accounts(settings)
        sessions = self._login_sessions(accounts, settings.get("login", {}))

        for endpoint_key in ("registration", "password_change"):
            endpoint = settings.get(endpoint_key, {})
            if not isinstance(endpoint, dict) or not endpoint.get("enabled", False):
                continue
            if not self._safe_endpoint(endpoint):
                continue
            session = None
            account_name = None
            if endpoint_key == "password_change":
                account_name = endpoint.get("account")
                session = sessions.get(str(account_name))
                if session is None:
                    continue
            for rule_name, password in test_passwords.items():
                self._check_password(
                    endpoint_key,
                    endpoint,
                    session,
                    account_name,
                    rule_name,
                    password,
                    settings,
                )

        self._check_login_protection(settings, accounts)
        return self.findings

    @staticmethod
    def _safe_endpoint(endpoint: Dict[str, Any]) -> bool:
        method = str(endpoint.get("method", "POST")).upper()
        path = endpoint.get("path")
        return (
            method in {"POST", "PUT", "PATCH"}
            and isinstance(path, str)
            and path.startswith("/")
            and not path.startswith("//")
        )

    @staticmethod
    def _accounts(settings: Dict[str, Any]) -> List[Dict[str, str]]:
        raw = settings.get("accounts", [])
        if not isinstance(raw, list):
            return []
        accounts = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            values = {
                key: item.get(key)
                for key in ("name", "username", "password")
            }
            if all(isinstance(value, str) and value for value in values.values()):
                accounts.append(values)
        return accounts

    @staticmethod
    def _test_passwords(rules: Dict[str, Any]) -> Dict[str, str]:
        try:
            minimum = max(4, int(rules.get("min_length", 12)))
        except (TypeError, ValueError):
            minimum = 12
        passwords: Dict[str, str] = {}
        if "min_length" in rules:
            passwords["minimum_length"] = ("Aa1!" * ((minimum - 1 + 3) // 4))[: minimum - 1]
        if rules.get("require_uppercase", False):
            passwords["uppercase"] = "weakpassword1!"
        if rules.get("require_lowercase", False):
            passwords["lowercase"] = "WEAKPASSWORD1!"
        if rules.get("require_digit", False):
            passwords["digit"] = "WeakPassword!"
        if rules.get("require_special", False):
            passwords["special"] = "WeakPassword1"
        common = rules.get("common_passwords", [])
        if isinstance(common, list) and common:
            common_value = next((value for value in common if isinstance(value, str) and value), "")
            if common_value:
                passwords["common_password"] = common_value
        return passwords

    def _login_sessions(
        self, accounts: Iterable[Dict[str, str]], login: Any
    ) -> Dict[str, requests.Session]:
        if not isinstance(login, dict) or not self._safe_login(login):
            return {}
        sessions: Dict[str, requests.Session] = {}
        for account in accounts:
            session = requests.Session()
            session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
            payload = {
                str(login.get("username_field", "username")): account["username"],
                str(login.get("password_field", "password")): account["password"],
            }
            try:
                response = self._send(
                    session,
                    login,
                    payload,
                )
            except (requests.RequestException, ValueError):
                continue
            statuses = login.get("success_statuses", self._success_statuses)
            if not isinstance(statuses, list):
                statuses = self._success_statuses
            if response.status_code in statuses:
                sessions[account["name"]] = session
        return sessions

    def _check_password(
        self,
        endpoint_key: str,
        endpoint: Dict[str, Any],
        session: requests.Session | None,
        account_name: Any,
        rule_name: str,
        password: str,
        settings: Dict[str, Any],
    ) -> None:
        payload = dict(endpoint.get("fields", {})) if isinstance(endpoint.get("fields"), dict) else {}
        password_field = str(endpoint.get("password_field", "password"))
        payload[password_field] = password
        username_field = endpoint.get("username_field")
        if username_field and endpoint.get("username"):
            payload[str(username_field)] = endpoint["username"]
        try:
            response = self._send(session or self.session, endpoint, payload)
        except (requests.RequestException, ValueError):
            return
        accepted = self._is_accepted(response, endpoint)
        if accepted:
            self.add_finding(
                f"PASSWORD-{len(self.findings) + 1:03d}",
                "AUTH",
                "High",
                f"{endpoint_key.replace('_', ' ').title()} accepted a password that violates the {rule_name.replace('_', ' ')} rule.",
                json.dumps(
                    {
                        "endpoint": endpoint["path"],
                        "account": account_name or "[registration-test]",
                        "rule": rule_name,
                        "accepted_weak_input": password,
                        "status": response.status_code,
                        "response_excerpt": self._redact(
                            response.text[: int(settings.get("max_evidence_bytes", 500))]
                        ),
                    },
                    sort_keys=True,
                ),
                "Enforce the configured password policy server-side before creating or changing credentials.",
                "A07:2021 Identification and Authentication Failures",
                cvss=7.5,
                confidence="high",
            )

    def _check_login_protection(
        self, settings: Dict[str, Any], accounts: List[Dict[str, str]]
    ) -> None:
        login = settings.get("login", {})
        protection = settings.get("login_protection", {})
        if not isinstance(login, dict) or not self._safe_login(login):
            return
        if not isinstance(protection, dict):
            return
        account = accounts[0] if accounts else None
        username = protection.get("username") or (account or {}).get("username")
        wrong_password = protection.get("wrong_password", "Definitely-not-the-right-password-1!")
        if not isinstance(username, str) or not username:
            return
        for check_name in ("rate_limit", "lockout"):
            check = protection.get(check_name, {})
            if not isinstance(check, dict) or not check.get("enabled", False):
                continue
            try:
                attempts = min(max(int(check.get("attempts", 5)), 1), 10)
            except (TypeError, ValueError):
                attempts = 5
            statuses = check.get("expected_statuses", [429, 423])
            if not isinstance(statuses, list):
                statuses = [429, 423]
            responses = []
            session = requests.Session()
            session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
            for _ in range(attempts):
                payload = {
                    str(login.get("username_field", "username")): username,
                    str(login.get("password_field", "password")): wrong_password,
                }
                try:
                    responses.append(self._send(session, login, payload))
                except (requests.RequestException, ValueError):
                    break
            protected = any(
                response.status_code in statuses or response.headers.get("Retry-After")
                for response in responses
            )
            if responses and not protected:
                self.add_finding(
                    f"PASSWORD-{len(self.findings) + 1:03d}",
                    "AUTH",
                    "High",
                    f"Login endpoint did not demonstrate configured {check_name.replace('_', ' ')} protection.",
                    json.dumps(
                        {
                            "endpoint": login["path"],
                            "check": check_name,
                            "attempts": len(responses),
                            "statuses": [response.status_code for response in responses],
                            "username": "[REDACTED]",
                        },
                        sort_keys=True,
                    ),
                    "Apply server-side throttling and temporary lockout controls to repeated failed authentication attempts.",
                    "A07:2021 Identification and Authentication Failures",
                    cvss=7.5,
                    confidence="medium",
                )

    def _send(
        self,
        session: requests.Session,
        endpoint: Dict[str, Any],
        payload: Dict[str, Any],
    ) -> requests.Response:
        return self.request(
            str(endpoint.get("method", "POST")).upper(),
            str(endpoint["path"]),
            session=session,
            json=payload if endpoint.get("format") == "json" else None,
            data=None if endpoint.get("format") == "json" else payload,
        )

    @classmethod
    def _is_accepted(cls, response: requests.Response, endpoint: Dict[str, Any]) -> bool:
        statuses = endpoint.get("success_statuses", cls._success_statuses)
        if not isinstance(statuses, list):
            statuses = cls._success_statuses
        return response.status_code in statuses

    @staticmethod
    def _safe_login(login: Dict[str, Any]) -> bool:
        return (
            isinstance(login.get("path"), str)
            and login["path"].startswith("/")
            and str(login.get("method", "POST")).upper() == "POST"
        )

    @staticmethod
    def _redact(value: str) -> str:
        value = re.sub(
            r"(?i)(authorization|cookie|password|token|secret|api[-_]?key)\s*[:=]\s*[^,\s}]+",
            r"\1=[REDACTED]",
            value,
        )
        return re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "Bearer [REDACTED]", value)
