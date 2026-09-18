"""Opt-in, non-destructive SQL injection detection checks."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from core.base import Scanner


class SqliScanner(Scanner):
    """Probe explicitly configured input points with safe SQLi indicators."""

    name = "sqli"
    _payloads = (
        ("error", "'"),
        ("boolean_true", "' OR '1'='1"),
        ("boolean_false", "' AND '1'='2"),
    )
    _error_signatures = (
        r"sql syntax.*mysql",
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"sqlite error",
        r"sqlite3\.operationalerror",
        r"postgresql.*error",
        r"pg::syntaxerror",
        r"ora-\d{5}",
        r"oracle.*error",
        r"microsoft sql server",
        r"odbc sql server driver",
        r"jdbc.*sql",
        r"syntax error.*near",
        r"unclosed quotation mark",
    )

    def scan(self) -> List[Any]:
        settings = self.config.get("sqli", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings
        if settings.get("deep_scan", False):
            return self.findings

        endpoints = self._endpoints(settings)
        if not endpoints:
            return self.findings
        discovered = self._discover()
        for endpoint in endpoints:
            if endpoint["path"] not in discovered:
                continue
            for input_point in endpoint["inputs"]:
                self._check_input(endpoint, input_point, settings)
        return self.findings

    def _discover(self) -> set[str]:
        from scanners.dast import DastScanner

        discovery = DastScanner(self.target_url, self.config)
        response = discovery.request("GET", "/")
        return set(discovery.discover_endpoints(response))

    @staticmethod
    def _endpoints(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = settings.get("endpoints", [])
        if not isinstance(raw, list):
            return []
        endpoints = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            method = str(item.get("method", "GET")).upper()
            inputs = item.get("inputs", [])
            if (
                isinstance(path, str)
                and path.startswith("/")
                and not urlsplit(path).netloc
                and method in {"GET", "POST", "PUT", "PATCH"}
                and isinstance(inputs, list)
            ):
                normalized = [
                    point
                    for point in inputs
                    if isinstance(point, dict)
                    and isinstance(point.get("name"), str)
                    and point.get("location", "query") in {"query", "form", "json", "header"}
                ]
                if normalized:
                    endpoints.append(
                        {
                            "path": path,
                            "method": method,
                            "format": item.get("format", "form"),
                            "fields": item.get("fields", {}),
                            "inputs": normalized,
                        }
                    )
        return endpoints

    def _check_input(
        self,
        endpoint: Dict[str, Any],
        input_point: Dict[str, Any],
        settings: Dict[str, Any],
    ) -> None:
        baseline = self._request_input(endpoint, input_point, "")
        if baseline is None:
            return
        baseline_text = baseline.text
        baseline_error = self._error_signature(baseline_text)
        baseline_fingerprint = self._fingerprint(baseline)
        for payload_name, payload in self._payloads:
            response = self._request_input(endpoint, input_point, payload)
            if response is None:
                continue
            error = self._error_signature(response.text)
            if error and not baseline_error:
                self._finding(
                    endpoint,
                    input_point,
                    payload_name,
                    payload,
                    response,
                    "database error signature appeared after the probe",
                    settings,
                )
                continue
            if payload_name == "boolean_false":
                true_response = self._request_input(
                    endpoint, input_point, self._payloads[1][1]
                )
                if true_response is not None and self._boolean_diff(
                    true_response, response, baseline_fingerprint
                ):
                    self._finding(
                        endpoint,
                        input_point,
                        payload_name,
                        payload,
                        response,
                        "true/false boolean probes produced a meaningful response difference",
                        settings,
                    )

    def _request_input(
        self,
        endpoint: Dict[str, Any],
        input_point: Dict[str, Any],
        value: str,
    ) -> requests.Response | None:
        location = input_point.get("location", "query")
        name = input_point["name"]
        path = endpoint["path"]
        data = dict(endpoint.get("fields", {})) if isinstance(endpoint.get("fields"), dict) else {}
        headers: Dict[str, str] = {}
        json_body = None
        if location == "query":
            parsed = urlsplit(path)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[name] = value
            path = urlunsplit(("", "", parsed.path, urlencode(query), parsed.fragment))
        elif location == "form":
            data[name] = value
        elif location == "json":
            json_body = dict(data)
            json_body[name] = value
        elif location == "header":
            headers[name] = value
        try:
            return self.request(
                endpoint["method"],
                path,
                data=data if location == "form" else None,
                json=json_body if location == "json" else None,
                headers=headers or None,
            )
        except (requests.RequestException, ValueError):
            return None

    @classmethod
    def _error_signature(cls, body: str) -> str | None:
        lowered = body.lower()
        for signature in cls._error_signatures:
            if re.search(signature, lowered):
                return signature
        return None

    @staticmethod
    def _fingerprint(response: requests.Response) -> tuple[int, int, str | None]:
        return response.status_code, len(response.text), response.headers.get("Content-Type")

    @staticmethod
    def _boolean_diff(
        true_response: requests.Response,
        false_response: requests.Response,
        baseline: tuple[int, int, str | None],
    ) -> bool:
        true_fp = SqliScanner._fingerprint(true_response)
        false_fp = SqliScanner._fingerprint(false_response)
        return (
            true_fp != false_fp
            and true_fp != baseline
            and false_fp != baseline
            and abs(true_fp[1] - false_fp[1]) >= 20
        )

    def _finding(
        self,
        endpoint: Dict[str, Any],
        input_point: Dict[str, Any],
        payload_name: str,
        payload: str,
        response: requests.Response,
        reason: str,
        settings: Dict[str, Any],
    ) -> None:
        self.add_finding(
            f"SQLI-{len(self.findings) + 1:03d}",
            "API",
            "High",
            f"Potential SQL injection behavior detected at {endpoint['path']} ({input_point['name']}).",
            json.dumps(
                {
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "parameter": input_point["name"],
                    "location": input_point.get("location", "query"),
                    "payload": self._sanitize_payload(payload),
                    "signal": reason,
                    "status": response.status_code,
                    "response_excerpt": self._redact(
                        response.text[: int(settings.get("max_evidence_bytes", 500))]
                    ),
                },
                sort_keys=True,
            ),
            "Use parameterized queries or prepared statements and avoid returning database errors to clients.",
            "A03:2021 Injection",
            cvss=8.2,
            confidence="medium",
        )

    @staticmethod
    def _sanitize_payload(payload: str) -> str:
        return payload.replace("'", "[quote]")

    @staticmethod
    def _redact(value: str) -> str:
        value = re.sub(
            r"(?i)(authorization|cookie|password|token|secret|api[-_]?key)\s*[:=]\s*[^,\s}]+",
            r"\1=[REDACTED]",
            value,
        )
        return re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "Bearer [REDACTED]", value)
