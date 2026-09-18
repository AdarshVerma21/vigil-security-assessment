"""Detection-only static application security checks."""

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from core.base import Scanner
from core.models import Finding


class SastScanner(Scanner):
    """Scan local source files for high-signal insecure patterns."""

    name = "sast"
    _extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".yaml", ".yml"}
    _ignored = {".git", ".venv", "node_modules", "__pycache__", "reports"}
    _secret_pattern = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|access[_-]?key)\b"
        r"\s*[:=]\s*[\"'][^\"']{8,}[\"']"
    )
    _patterns = (
        (
            "SAST-001",
            re.compile(r"(?i)\beval\s*\(|\bexec\s*\("),
            "Dynamic code execution detected.",
            "Remove dynamic execution or replace it with an allow-listed operation.",
            "A03:2021 Injection",
            "High",
        ),
        (
            "SAST-002",
            re.compile(r"(?i)(innerHTML\s*=|dangerouslySetInnerHTML)"),
            "Direct HTML injection sink detected.",
            "Use safe text rendering or sanitize trusted HTML with a strict allow-list.",
            "A03:2021 Injection",
            "Medium",
        ),
        (
            "SAST-003",
            re.compile(r"(?i)\b(subprocess|os\.system)\b.*shell\s*=\s*True"),
            "Shell execution with shell parsing enabled detected.",
            "Pass argument arrays and disable shell parsing unless strictly required.",
            "A03:2021 Injection",
            "High",
        ),
        (
            "SAST-004",
            re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false)"),
            "TLS certificate verification appears disabled.",
            "Enable certificate verification in all non-test environments.",
            "A02:2021 Cryptographic Failures",
            "High",
        ),
    )

    def __init__(self, source_root: Path, target_url: str = "", config: Dict[str, Any] | None = None):
        super().__init__(target_url or "http://localhost", config)
        self.source_root = source_root.resolve()
        self._excluded = {
            Path(item).as_posix()
            for item in (config or {}).get("sast_exclude", [])
            if isinstance(item, str)
        }

    def _files(self) -> Iterable[Path]:
        for path in self.source_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self._extensions:
                continue
            if any(part in self._ignored for part in path.parts):
                continue
            yield path

    def scan(self) -> List[Finding]:
        seen: Set[tuple[str, str, int]] = set()
        for path in self._files():
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            relative = path.relative_to(self.source_root)
            if relative.as_posix() in self._excluded:
                continue
            for line_number, line in enumerate(lines, 1):
                if self._secret_pattern.search(line):
                    key = ("secret", str(relative), line_number)
                    if key not in seen:
                        seen.add(key)
                        self.add_finding(
                            "SAST-005",
                            "SAST",
                            "Critical",
                            "Potential hardcoded credential or secret detected.",
                            f"{relative}:{line_number} ({self._redact(line.strip())})",
                            "Move secrets to an environment-backed secret store and rotate exposed values.",
                            "A02:2021 Cryptographic Failures",
                        )
                for finding_id, pattern, description, remediation, owasp, severity in self._patterns:
                    if pattern.search(line):
                        key = (finding_id, str(relative), line_number)
                        if key not in seen:
                            seen.add(key)
                            self.add_finding(
                                finding_id,
                                "SAST",
                                severity,
                                description,
                                f"{relative}:{line_number} ({line.strip()[:180]})",
                                remediation,
                                owasp,
                            )
        return self.findings

    @staticmethod
    def _redact(line: str) -> str:
        return re.sub(r"(=|:)\s*[\"'][^\"']+[\"']", r"\1 '<redacted>'", line)
