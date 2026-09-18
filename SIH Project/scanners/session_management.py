"""Opt-in authenticated session-management checks."""

from __future__ import annotations

import json
import math
import re
import time
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List

import requests

from core.base import Scanner


class SessionManagementScanner(Scanner):
    """Check session token strength and lifecycle controls."""

    name = "session-management"
    _default_success_statuses = [200, 201, 204, 302]
    _default_protected_success = [200, 204]
    _default_expired_statuses = [401, 403, 419, 440]
    _token_name_re = re.compile(r"(?i)(session|sess|auth|token|jwt|sid)")

    def scan(self) -> List[Any]:
        settings = self.config.get("session_management", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings

        accounts = self._accounts(settings)
        login = settings.get("login", {})
        if not accounts or not self._safe_auth_endpoint(login):
            return self.findings

        token_catalog: Dict[str, Dict[str, str]] = {}
        for account in accounts:
            session = requests.Session()
            session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
            pre_login_tokens = self._prefetch_pre_login_tokens(session, login)
            response = self._authenticate(session, account, login)
            if response is None:
                continue
            auth_tokens = self._session_tokens(session.cookies, settings)
            if not auth_tokens:
                continue
            token_catalog[account["name"]] = auth_tokens
            self._check_cookie_flags(auth_tokens, session.cookies)
            self._check_token_entropy(auth_tokens, settings)
            self._check_session_fixation(pre_login_tokens, auth_tokens, account)

        self._check_cross_account_predictability(token_catalog)
        self._check_logout_invalidation(settings, accounts)
        self._check_session_expiry(settings, accounts)
        return self.findings

    @staticmethod
    def _accounts(settings: Dict[str, Any]) -> List[Dict[str, str]]:
        raw = settings.get("accounts", [])
        if not isinstance(raw, list):
            return []
        accounts: List[Dict[str, str]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            values = {key: item.get(key) for key in ("name", "username", "password")}
            if all(isinstance(value, str) and value for value in values.values()):
                accounts.append(values)
        return accounts

    @staticmethod
    def _safe_auth_endpoint(endpoint: Any) -> bool:
        if not isinstance(endpoint, dict):
            return False
        path = endpoint.get("path")
        method = str(endpoint.get("method", "POST")).upper()
        return (
            isinstance(path, str)
            and path.startswith("/")
            and not path.startswith("//")
            and method in {"POST", "PUT", "PATCH"}
        )

    def _prefetch_pre_login_tokens(
        self, session: requests.Session, login: Dict[str, Any]
    ) -> Dict[str, str]:
        prefetched: Dict[str, str] = {}
        pre_login = login.get("prefetch_path", login.get("path", "/"))
        if not isinstance(pre_login, str) or not pre_login.startswith("/"):
            return prefetched
        try:
            self.request("GET", pre_login, session=session)
        except (requests.RequestException, ValueError):
            return prefetched
        return self._session_tokens(session.cookies, {})

    def _authenticate(
        self, session: requests.Session, account: Dict[str, str], login: Dict[str, Any]
    ) -> requests.Response | None:
        payload = {
            str(login.get("username_field", "username")): account["username"],
            str(login.get("password_field", "password")): account["password"],
        }
        if isinstance(login.get("fields"), dict):
            payload.update({str(key): value for key, value in login["fields"].items()})
        try:
            response = self.request(
                str(login.get("method", "POST")).upper(),
                str(login["path"]),
                session=session,
                json=payload if login.get("format") == "json" else None,
                data=None if login.get("format") == "json" else payload,
            )
        except (requests.RequestException, ValueError):
            return None
        statuses = login.get("success_statuses", self._default_success_statuses)
        if not isinstance(statuses, list):
            statuses = self._default_success_statuses
        return response if response.status_code in statuses else None

    def _session_tokens(
        self, jar: requests.cookies.RequestsCookieJar, settings: Dict[str, Any]
    ) -> Dict[str, str]:
        patterns = settings.get("token_cookie_patterns", [])
        custom_patterns = []
        if isinstance(patterns, list):
            custom_patterns = [item.lower() for item in patterns if isinstance(item, str)]
        tokens: Dict[str, str] = {}
        for cookie in jar:
            name = str(cookie.name)
            lower = name.lower()
            is_session_cookie = bool(self._token_name_re.search(name))
            if custom_patterns:
                is_session_cookie = any(fragment in lower for fragment in custom_patterns)
            if is_session_cookie and isinstance(cookie.value, str) and cookie.value:
                tokens[name] = cookie.value
        return tokens

    def _check_cookie_flags(
        self,
        tokens: Dict[str, str],
        jar: requests.cookies.RequestsCookieJar,
    ) -> None:
        selected = {name for name in tokens.keys()}
        for cookie in jar:
            if cookie.name not in selected:
                continue
            rest_keys = {str(key).lower() for key in cookie._rest.keys()}
            same_site = str(cookie._rest.get("SameSite", cookie._rest.get("samesite", ""))).lower()
            if not cookie.secure:
                self._add_session_finding(
                    "Medium",
                    f"Session cookie {cookie.name} is missing the Secure attribute.",
                    {
                        "cookie": cookie.name,
                        "missing_flag": "Secure",
                    },
                    "Set Secure on all session cookies so browsers only send them over HTTPS.",
                )
            if "httponly" not in rest_keys:
                self._add_session_finding(
                    "Medium",
                    f"Session cookie {cookie.name} is missing the HttpOnly attribute.",
                    {
                        "cookie": cookie.name,
                        "missing_flag": "HttpOnly",
                    },
                    "Set HttpOnly on session cookies to reduce script-level token access.",
                )
            if not same_site:
                self._add_session_finding(
                    "Low",
                    f"Session cookie {cookie.name} is missing the SameSite attribute.",
                    {
                        "cookie": cookie.name,
                        "missing_flag": "SameSite",
                    },
                    "Set SameSite=Lax or SameSite=Strict for session cookies unless cross-site flow is required.",
                )

    def _check_token_entropy(
        self, tokens: Dict[str, str], settings: Dict[str, Any]
    ) -> None:
        try:
            minimum_length = max(12, int(settings.get("min_token_length", 24)))
        except (TypeError, ValueError):
            minimum_length = 24
        try:
            minimum_entropy = max(2.5, float(settings.get("min_token_entropy", 3.5)))
        except (TypeError, ValueError):
            minimum_entropy = 3.5
        try:
            minimum_unique = max(6, int(settings.get("min_unique_characters", 10)))
        except (TypeError, ValueError):
            minimum_unique = 10

        for name, token in tokens.items():
            entropy = self._shannon_entropy(token)
            unique_count = len(set(token))
            if len(token) < minimum_length or entropy < minimum_entropy or unique_count < minimum_unique:
                self._add_session_finding(
                    "High",
                    f"Session token {name} appears weak or predictable.",
                    {
                        "cookie": name,
                        "token_length": len(token),
                        "unique_characters": unique_count,
                        "entropy_bits_per_char": round(entropy, 3),
                        "token_preview": self._token_preview(token),
                    },
                    "Use cryptographically secure random session identifiers with sufficient length and entropy.",
                )

    def _check_session_fixation(
        self,
        pre_login_tokens: Dict[str, str],
        post_login_tokens: Dict[str, str],
        account: Dict[str, str],
    ) -> None:
        for name, pre_value in pre_login_tokens.items():
            post_value = post_login_tokens.get(name)
            if post_value and post_value == pre_value:
                self._add_session_finding(
                    "High",
                    f"Possible session fixation detected for cookie {name}.",
                    {
                        "cookie": name,
                        "account": account["name"],
                        "token_preview": self._token_preview(post_value),
                    },
                    "Regenerate a fresh session identifier after successful authentication.",
                )

    def _check_cross_account_predictability(
        self, token_catalog: Dict[str, Dict[str, str]]
    ) -> None:
        collisions: Dict[str, List[str]] = defaultdict(list)
        for account_name, tokens in token_catalog.items():
            for cookie_name, value in tokens.items():
                collisions[f"{cookie_name}:{value}"].append(account_name)
        for key, accounts in collisions.items():
            if len(accounts) < 2:
                continue
            cookie_name, _ = key.split(":", 1)
            self._add_session_finding(
                "Critical",
                f"Identical session token value detected across multiple accounts for cookie {cookie_name}.",
                {
                    "cookie": cookie_name,
                    "accounts": sorted(accounts),
                },
                "Issue unique per-session identifiers for each authenticated account.",
            )

    def _check_logout_invalidation(
        self, settings: Dict[str, Any], accounts: List[Dict[str, str]]
    ) -> None:
        logout = settings.get("logout", {})
        if not isinstance(logout, dict) or not logout.get("enabled", False):
            return
        if not self._safe_auth_endpoint(logout):
            return
        account = self._pick_account(accounts, logout.get("account"))
        if account is None:
            return
        protected_path = self._protected_probe_path(settings)
        if protected_path is None:
            return
        session = requests.Session()
        session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
        if self._authenticate(session, account, settings.get("login", {})) is None:
            return
        baseline = self._probe_protected(session, protected_path, settings)
        if baseline is None:
            return
        if baseline.status_code not in self._protected_success_statuses(settings):
            return
        payload = logout.get("fields", {}) if isinstance(logout.get("fields"), dict) else {}
        try:
            self.request(
                str(logout.get("method", "POST")).upper(),
                str(logout["path"]),
                session=session,
                json=payload if logout.get("format") == "json" else None,
                data=None if logout.get("format") == "json" else payload,
            )
            replay = self._probe_protected(session, protected_path, settings)
        except (requests.RequestException, ValueError):
            return
        if replay is None:
            return
        if replay.status_code in self._protected_success_statuses(settings):
            self._add_session_finding(
                "High",
                "Session appears valid after logout.",
                {
                    "account": account["name"],
                    "logout_path": logout["path"],
                    "protected_path": protected_path,
                    "status_before_logout": baseline.status_code,
                    "status_after_logout": replay.status_code,
                },
                "Invalidate server-side session state and revoke active tokens at logout.",
            )

    def _check_session_expiry(
        self, settings: Dict[str, Any], accounts: List[Dict[str, str]]
    ) -> None:
        expiry = settings.get("expiry", {})
        if not isinstance(expiry, dict) or not expiry.get("enabled", False):
            return
        account = self._pick_account(accounts, expiry.get("account"))
        if account is None:
            return
        protected_path = self._protected_probe_path(settings)
        if protected_path is None:
            return
        try:
            wait_seconds = min(max(int(expiry.get("wait_seconds", 2)), 1), 30)
        except (TypeError, ValueError):
            wait_seconds = 2
        session = requests.Session()
        session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
        if self._authenticate(session, account, settings.get("login", {})) is None:
            return
        baseline = self._probe_protected(session, protected_path, settings)
        if baseline is None:
            return
        if baseline.status_code not in self._protected_success_statuses(settings):
            return
        time.sleep(wait_seconds)
        replay = self._probe_protected(session, protected_path, settings)
        if replay is None:
            return
        if replay.status_code in self._expected_expired_statuses(expiry):
            return
        if self._is_login_redirect(replay, settings.get("login", {})):
            return
        self._add_session_finding(
            "Medium",
            "Session remained valid after configured idle timeout window.",
            {
                "account": account["name"],
                "protected_path": protected_path,
                "wait_seconds": wait_seconds,
                "status_before_wait": baseline.status_code,
                "status_after_wait": replay.status_code,
            },
            "Enforce server-side idle and absolute session expiration with token revocation.",
        )

    @staticmethod
    def _pick_account(
        accounts: List[Dict[str, str]], requested_name: Any
    ) -> Dict[str, str] | None:
        if not accounts:
            return None
        if isinstance(requested_name, str) and requested_name:
            match = next((item for item in accounts if item["name"] == requested_name), None)
            if match is not None:
                return match
        return accounts[0]

    def _protected_probe_path(self, settings: Dict[str, Any]) -> str | None:
        raw = settings.get("protected_paths", [])
        if not isinstance(raw, list):
            return None
        for path in raw:
            if isinstance(path, str) and path.startswith("/") and not path.startswith("//"):
                return path
        return None

    def _probe_protected(
        self, session: requests.Session, path: str, settings: Dict[str, Any]
    ) -> requests.Response | None:
        method = str(settings.get("protected_method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            method = "GET"
        try:
            return self.request(method, path, session=session)
        except (requests.RequestException, ValueError):
            return None

    def _protected_success_statuses(self, settings: Dict[str, Any]) -> List[int]:
        statuses = settings.get("protected_success_statuses", self._default_protected_success)
        if not isinstance(statuses, list):
            return self._default_protected_success
        return [int(code) for code in statuses if isinstance(code, int)]

    def _expected_expired_statuses(self, expiry: Dict[str, Any]) -> List[int]:
        statuses = expiry.get("expected_statuses", self._default_expired_statuses)
        if not isinstance(statuses, list):
            return self._default_expired_statuses
        return [int(code) for code in statuses if isinstance(code, int)]

    @staticmethod
    def _is_login_redirect(response: requests.Response, login: Any) -> bool:
        if response.status_code not in {301, 302, 303, 307, 308}:
            return False
        if not isinstance(login, dict):
            return False
        login_path = login.get("path")
        location = response.headers.get("Location", "")
        return isinstance(login_path, str) and isinstance(location, str) and login_path in location

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        length = len(value)
        if length == 0:
            return 0.0
        counts = Counter(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def _token_preview(token: str) -> str:
        if len(token) <= 8:
            return "****"
        return f"{token[:4]}...{token[-4:]}"

    def _add_session_finding(
        self, severity: str, description: str, evidence: Dict[str, Any], remediation: str
    ) -> None:
        redacted_evidence = json.dumps(evidence, sort_keys=True)
        self.add_finding(
            f"SESSION-{len(self.findings) + 1:03d}",
            "AUTH",
            severity,
            description,
            redacted_evidence,
            remediation,
            "A07:2021 Identification and Authentication Failures",
            cvss=self._cvss_from_severity(severity),
            confidence="medium" if severity in {"Low", "Medium"} else "high",
        )

    @staticmethod
    def _cvss_from_severity(severity: str) -> float:
        mapping = {"Low": 3.7, "Medium": 5.9, "High": 8.0, "Critical": 9.3}
        return mapping.get(severity, 5.0)
