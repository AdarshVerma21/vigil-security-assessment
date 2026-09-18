"""Opt-in, bounded rate-limit checks for explicitly authorized endpoints."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List
from urllib.parse import urlsplit

import requests

from core.base import Scanner


class RateLimitScanner(Scanner):
    """Send a conservative bounded burst and look for throttling signals."""

    name = "rate-limit"
    _default_throttle_statuses = (401, 403, 423, 429)
    _max_requests = 10
    _min_interval = 0.05
    _max_cooldown = 10.0

    def scan(self) -> List[Any]:
        settings = self.config.get("rate_limit", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings

        endpoints = settings.get("endpoints", [])
        if not isinstance(endpoints, list):
            return self.findings

        count = self._bounded_int(settings.get("count", 5), 1, self._max_requests)
        interval = self._bounded_float(
            settings.get("interval_seconds", 0.25), self._min_interval, 60.0
        )
        cooldown = self._bounded_float(
            settings.get("cooldown_seconds", 2.0), 0.0, self._max_cooldown
        )
        statuses = self._status_set(settings.get("throttle_statuses"))

        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not self._safe_endpoint(endpoint):
                continue
            self._check_endpoint(endpoint, count, interval, cooldown, statuses, settings)
        return self.findings

    def _check_endpoint(
        self,
        endpoint: Dict[str, Any],
        count: int,
        interval: float,
        cooldown: float,
        throttle_statuses: set[int],
        settings: Dict[str, Any],
    ) -> None:
        session = requests.Session()
        session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
        payload = endpoint.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        responses: List[requests.Response] = []
        try:
            for attempt in range(count):
                try:
                    response = self.request(
                        str(endpoint.get("method", "POST")).upper(),
                        str(endpoint["path"]),
                        session=session,
                        json=payload if endpoint.get("format") == "json" else None,
                        data=None if endpoint.get("format") == "json" else payload,
                    )
                except (requests.RequestException, ValueError):
                    break
                responses.append(response)
                if self._is_throttled(response, throttle_statuses):
                    break
                if attempt < count - 1:
                    time.sleep(interval)
        finally:
            if cooldown:
                time.sleep(cooldown)

        if not responses or any(
            self._is_throttled(response, throttle_statuses) for response in responses
        ):
            return
        self.add_finding(
            f"RATE-{len(self.findings) + 1:03d}",
            "AUTH",
            "Medium",
            f"No rate-limiting response was observed on {endpoint['path']}.",
            json.dumps(
                {
                    "endpoint": endpoint["path"],
                    "method": str(endpoint.get("method", "POST")).upper(),
                    "request_count": len(responses),
                    "response_codes": [response.status_code for response in responses],
                    "interval_seconds": interval,
                    "cooldown_seconds": cooldown,
                    "payload": "[REDACTED]",
                },
                sort_keys=True,
            ),
            "Apply endpoint-appropriate throttling, backoff, and temporary lockout controls.",
            "A07:2021 Identification and Authentication Failures",
            cvss=6.5,
            confidence="medium",
        )

    @staticmethod
    def _safe_endpoint(endpoint: Dict[str, Any]) -> bool:
        path = endpoint.get("path")
        method = str(endpoint.get("method", "POST")).upper()
        return (
            isinstance(path, str)
            and path.startswith("/")
            and not path.startswith("//")
            and not urlsplit(path).netloc
            and method in {"GET", "POST", "PUT", "PATCH"}
        )

    @classmethod
    def _is_throttled(
        cls, response: requests.Response, throttle_statuses: set[int]
    ) -> bool:
        return response.status_code in throttle_statuses or bool(
            response.headers.get("Retry-After")
        )

    @classmethod
    def _status_set(cls, raw: Any) -> set[int]:
        if not isinstance(raw, list):
            return set(cls._default_throttle_statuses)
        statuses = set()
        for value in raw:
            try:
                statuses.add(int(value))
            except (TypeError, ValueError):
                continue
        return statuses or set(cls._default_throttle_statuses)

    @staticmethod
    def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
        try:
            return min(max(int(value), minimum), maximum)
        except (TypeError, ValueError):
            return minimum

    @staticmethod
    def _bounded_float(value: Any, minimum: float, maximum: float) -> float:
        try:
            return min(max(float(value), minimum), maximum)
        except (TypeError, ValueError):
            return minimum
