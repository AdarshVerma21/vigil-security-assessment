"""Opt-in active XSS checks verified with a headless browser."""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote, urlsplit

import requests

from core.base import Scanner

try:
    from playwright.sync_api import Error as PlaywrightError
except ImportError:
    class PlaywrightError(Exception):
        """Fallback type when Playwright is not installed."""


class XssScanner(Scanner):
    """Verify reflected and stored probes by observing a browser DOM marker."""

    name = "xss"
    _payload_template = (
        '<svg/onload="document.documentElement.dataset.vigilXss=\'{marker}\'">'
    )

    def scan(self) -> List[Any]:
        settings = self.config.get("xss", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return self.findings

        endpoints = self._endpoints(settings)
        if not endpoints:
            return self.findings
        try:
            from scanners.dast import DastScanner

            discovery = DastScanner(self.target_url, self.config)
            root = discovery.request("GET", "/")
            discovered = set(discovery.discover_endpoints(root))
        except (requests.RequestException, ValueError):
            return self.findings

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-sandbox"],
                )
                try:
                    for endpoint in endpoints:
                        if endpoint["path"] not in discovered:
                            continue
                        if endpoint["type"] == "reflected":
                            self._check_reflected(browser, endpoint, settings)
                        else:
                            self._check_stored(browser, endpoint, settings)
                finally:
                    browser.close()
        except PlaywrightError:
            return self.findings
        return self.findings

    @staticmethod
    def _endpoints(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = settings.get("endpoints", [])
        if not isinstance(raw, list):
            return []
        endpoints: List[Dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            location = item.get("location", "query")
            endpoint_type = item.get("type", "reflected")
            method = str(item.get("method", "GET")).upper()
            if (
                isinstance(path, str)
                and path.startswith("/")
                and not urlsplit(path).netloc
                and location in {"query", "form", "json"}
                and endpoint_type in {"reflected", "stored"}
                and method in {"GET", "POST", "PUT", "PATCH"}
                and isinstance(item.get("parameter"), str)
                and isinstance(item.get("view_path", path), str)
            ):
                endpoints.append(
                    {
                        "path": path,
                        "method": method,
                        "format": item.get("format", "form"),
                        "location": location,
                        "parameter": item["parameter"],
                        "fields": item.get("fields", {}),
                        "type": endpoint_type,
                        "view_path": item.get("view_path", path),
                        "browser_path": bool(item.get("browser_path", False)),
                        "accounts": item.get("accounts", []),
                    }
                )
        return endpoints

    def _check_reflected(
        self, browser: Any, endpoint: Dict[str, Any], settings: Dict[str, Any]
    ) -> None:
        marker = f"VIGIL_XSS_{secrets.token_hex(6)}"
        payload = self._payload(marker)
        browser_path = self._browser_path(endpoint, payload)
        if browser_path is None:
            return
        context = browser.new_context()
        try:
            if endpoint["location"] != "query":
                session = requests.Session()
                self._submit(session, endpoint, payload)
                self._copy_cookies(context, session)
            page = context.new_page()
            page.goto(self._absolute(browser_path), wait_until="domcontentloaded")
            if self._marker_present(page, marker):
                self._add_finding(
                    endpoint,
                    payload,
                    marker,
                    page,
                    "reflected payload executed and set the VIGIL DOM marker",
                    settings,
                )
        except (ValueError, PlaywrightError):
            return
        finally:
            context.close()

    def _check_stored(
        self, browser: Any, endpoint: Dict[str, Any], settings: Dict[str, Any]
    ) -> None:
        accounts = self._accounts(endpoint, settings)
        if not accounts:
            return
        submitter = accounts[0]
        session = self._login(submitter, settings.get("login", {}))
        if session is None:
            return
        marker = f"VIGIL_XSS_{secrets.token_hex(6)}"
        payload = self._payload(marker)
        try:
            self._submit(session, endpoint, payload)
        except (requests.RequestException, ValueError):
            return
        for viewer in accounts:
            viewer_session = self._login(viewer, settings.get("login", {}))
            if viewer_session is None:
                continue
            context = browser.new_context()
            try:
                self._copy_cookies(context, viewer_session)
                page = context.new_page()
                page.goto(self._absolute(endpoint["view_path"]), wait_until="domcontentloaded")
                if self._marker_present(page, marker):
                    self._add_finding(
                        endpoint,
                        payload,
                        marker,
                        page,
                        f"stored payload executed when viewed by account {viewer['name']}",
                        settings,
                    )
            except (ValueError, PlaywrightError):
                continue
            finally:
                context.close()

    @staticmethod
    def _payload(marker: str) -> str:
        return XssScanner._payload_template.format(marker=marker)

    @staticmethod
    def _accounts(
        endpoint: Dict[str, Any], settings: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        raw = endpoint.get("accounts") or settings.get("accounts", [])
        if not isinstance(raw, list):
            return []
        result = []
        for item in raw:
            if isinstance(item, dict) and all(
                isinstance(item.get(key), str) and item[key]
                for key in ("name", "username", "password")
            ):
                result.append(
                    {
                        "name": item["name"],
                        "username": item["username"],
                        "password": item["password"],
                    }
                )
        return result

    def _login(
        self, account: Dict[str, str], login: Any
    ) -> requests.Session | None:
        if not isinstance(login, dict):
            return None
        path = login.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            return None
        session = requests.Session()
        payload = {
            str(login.get("username_field", "username")): account["username"],
            str(login.get("password_field", "password")): account["password"],
        }
        try:
            response = self.request(
                str(login.get("method", "POST")).upper(),
                path,
                session=session,
                json=payload if login.get("format") == "json" else None,
                data=None if login.get("format") == "json" else payload,
            )
        except (requests.RequestException, ValueError):
            return None
        statuses = login.get("success_statuses", [200, 201, 204, 302])
        return session if isinstance(statuses, list) and response.status_code in statuses else None

    def _submit(
        self, session: requests.Session, endpoint: Dict[str, Any], payload: str
    ) -> requests.Response:
        data = dict(endpoint["fields"]) if isinstance(endpoint["fields"], dict) else {}
        json_body = None
        if endpoint["location"] == "json":
            json_body = dict(data)
            json_body[endpoint["parameter"]] = payload
        elif endpoint["location"] == "form":
            data[endpoint["parameter"]] = payload
        else:
            raise ValueError("Stored XSS requires a form or JSON submission")
        return self.request(
            endpoint["method"],
            endpoint["path"],
            session=session,
            data=data if endpoint["location"] == "form" else None,
            json=json_body,
        )

    @staticmethod
    def _browser_path(endpoint: Dict[str, Any], payload: str) -> str | None:
        if endpoint["location"] != "query":
            return endpoint["view_path"] if endpoint.get("browser_path") else None
        separator = "&" if "?" in endpoint["path"] else "?"
        return f"{endpoint['path']}{separator}{endpoint['parameter']}={quote(payload)}"

    def _copy_cookies(self, context: Any, session: requests.Session) -> None:
        cookies = []
        for cookie in session.cookies:
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": (cookie.domain or urlsplit(self.target_url).hostname or "localhost").lstrip("."),
                    "path": cookie.path or "/",
                }
            )
        if cookies:
            context.add_cookies(cookies)

    def _marker_present(self, page: Any, marker: str) -> bool:
        return page.evaluate(
            "(expected) => document.documentElement.dataset.vigilXss === expected",
            marker,
        )

    def _add_finding(
        self,
        endpoint: Dict[str, Any],
        payload: str,
        marker: str,
        page: Any,
        reason: str,
        settings: Dict[str, Any],
    ) -> None:
        report_dir = Path(settings.get("evidence_dir", "reports/xss"))
        report_dir.mkdir(parents=True, exist_ok=True)
        screenshot = report_dir / f"{marker}.png"
        page.screenshot(path=str(screenshot), full_page=True)
        evidence = json.dumps(
            {
                "endpoint": endpoint["path"],
                "parameter": endpoint["parameter"],
                "location": endpoint["location"],
                "payload": self._sanitize_payload(payload),
                "dom_marker": marker,
                "execution": reason,
                "screenshot": str(screenshot),
            },
            sort_keys=True,
        )
        self.add_finding(
            f"XSS-{len(self.findings) + 1:03d}",
            "DAST",
            "High",
            f"Active XSS payload executed at {endpoint['path']} ({endpoint['parameter']}).",
            evidence,
            "Contextually encode untrusted output, sanitize HTML, and enforce a strict Content Security Policy.",
            "A03:2021 Injection",
            cvss=8.2,
            confidence="high",
        )

    def _absolute(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            if urlsplit(path).netloc != urlsplit(self.target_url).netloc:
                raise ValueError("Browser URL must match configured target")
            return path
        return f"{self.target_url}/{path.lstrip('/')}"

    @staticmethod
    def _sanitize_payload(payload: str) -> str:
        return re.sub(r"(?i)onload", "on[load]", payload)
