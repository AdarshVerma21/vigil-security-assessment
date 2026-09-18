"""Base class and safe HTTP helpers for scanners."""

from abc import ABC, abstractmethod
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests

from .models import Finding


class Scanner(ABC):
    """Base class for a detection-only security scanner.

    Scanners should use ``request`` for HTTP calls so that common safeguards
    such as timeouts and a descriptive user agent are applied consistently.
    """

    name = "base"

    def __init__(
        self,
        target_url: str,
        config: Optional[Dict[str, Any]] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        parsed_target = urlsplit(self.target_url)
        if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
            raise ValueError("Target URL must include an http or https scheme and host")
        self.config = config or {}
        self.session = session or requests.Session()
        self.session.headers.setdefault(
            "User-Agent", "WorldMonitor-Security-Assessment/0.1"
        )
        self.findings: List[Finding] = []
        self._capture_evidence = False
        self._last_artifact_ref: str | None = None
        self._artifact_sequence = 0

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the scanner and return findings."""

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Make a bounded request to the configured target.

        This helper intentionally does not follow caller-supplied arbitrary
        hosts: scanner paths are resolved against the configured target URL.
        """
        url = f"{self.target_url}/{path.lstrip('/')}"
        if path.startswith(("http://", "https://")):
            target = urlsplit(self.target_url)
            candidate = urlsplit(path)
            if (candidate.scheme, candidate.netloc) != (target.scheme, target.netloc):
                raise ValueError("Request URL must match the configured target")
            url = path
        session = kwargs.pop("session", self.session)
        kwargs.setdefault("timeout", self.config.get("request_timeout", 10))
        kwargs.setdefault("allow_redirects", False)
        request_snapshot = {
            "method": method.upper(),
            "url": url,
            "headers": self._redact(kwargs.get("headers") or dict(session.headers)),
            "body": self._redact(kwargs.get("json", kwargs.get("data"))),
        }
        response = session.request(method, url, **kwargs)
        if self._capture_evidence:
            self._last_artifact_ref = self._write_exchange_artifact(
                request_snapshot, response
            )
        return response

    def active_scope(self, settings: Dict[str, Any], module: str) -> bool:
        """Enable active checks only when explicitly enabled and target-scoped."""
        if not settings.get("enabled", False):
            return False
        raw_scope = settings.get("scope", settings.get("authorized_targets"))
        if not isinstance(raw_scope, list) or not raw_scope:
            logging.getLogger("vigil").warning(
                "%s skipped: no explicit target scope/allowlist configured", module
            )
            return False
        target = urlsplit(self.target_url)
        allowed = False
        for entry in raw_scope:
            if not isinstance(entry, str):
                continue
            candidate = urlsplit(entry.rstrip("/"))
            if candidate.scheme and candidate.netloc:
                allowed = (candidate.scheme, candidate.netloc) == (
                    target.scheme,
                    target.netloc,
                )
            else:
                allowed = bool(target.hostname) and (
                    entry.lower().lstrip(".") == target.hostname.lower()
                )
            if allowed:
                break
        if not allowed:
            logging.getLogger("vigil").warning(
                "%s skipped: target %s is outside the configured scope",
                module,
                self.target_url,
            )
            return False
        self._capture_evidence = True
        logging.getLogger("vigil").info(
            "%s enabled for explicitly scoped target %s", module, self.target_url
        )
        return True

    def _write_exchange_artifact(
        self, request_snapshot: Dict[str, Any], response: requests.Response
    ) -> str:
        """Persist a redacted request/response pair and return its artifact URI."""
        self._artifact_sequence += 1
        artifact_dir = Path(
            self.config.get("evidence_dir", "reports/artifacts")
        )
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{self.name}-{self._artifact_sequence:04d}.json"
        payload = {
            "request": request_snapshot,
            "response": {
                "status": response.status_code,
                "headers": self._redact(dict(response.headers)),
                "body": self._redact(response.text[:5000]),
            },
        }
        artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return f"artifact://{artifact_path.as_posix()}"

    @classmethod
    def _redact(cls, value: Any) -> Any:
        """Redact credential-like keys and values before evidence persistence."""
        secret_key = re.compile(
            r"(?i)(authorization|cookie|password|passwd|secret|token|api[-_]?key)"
        )
        if isinstance(value, dict):
            return {
                str(key): "[REDACTED]" if secret_key.search(str(key)) else cls._redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        if isinstance(value, tuple):
            return [cls._redact(item) for item in value]
        if isinstance(value, str):
            return secret_key.sub("[REDACTED]", value)[:5000]
        return value

    def add_finding(
        self,
        finding_id: str,
        category: str,
        severity: str,
        description: str,
        evidence: str,
        remediation: str,
        owasp_mapping: str,
        cvss: float | None = None,
        confidence: str = "medium",
        scanner: str | None = None,
        title: str | None = None,
        affected_component: str | None = None,
        cvss_vector: str | None = None,
        steps_to_reproduce: List[str] | None = None,
        poc_evidence: Dict[str, Any] | None = None,
        business_impact: str | None = None,
    ) -> Finding:
        """Record and return a finding."""
        finding = Finding(
            id=finding_id,
            category=category,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
            owasp_mapping=owasp_mapping,
            cvss=cvss,
            confidence=confidence,
            scanner=scanner or self.name,
            title=title or description,
            affected_component=affected_component or self.name,
            cvss_vector=cvss_vector or "",
            steps_to_reproduce=steps_to_reproduce,
            poc_evidence=poc_evidence
            or (
                {"artifact_ref": self._last_artifact_ref}
                if self._last_artifact_ref
                else None
            ),
            business_impact=business_impact or "",
        )
        self.findings.append(finding)
        return finding
