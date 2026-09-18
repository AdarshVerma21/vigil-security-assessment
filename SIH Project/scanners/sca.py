"""Detection-only software composition analysis using pip-audit."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from core.base import Scanner
from core.models import Finding


class ScaScanner(Scanner):
    """Scan Python dependencies without importing or executing application code."""

    name = "sca"

    def __init__(self, source_root: Path, target_url: str = "", config: Dict[str, Any] | None = None):
        super().__init__(target_url or "http://localhost", config)
        self.source_root = source_root.resolve()

    def scan(self) -> List[Finding]:
        manifest = self._manifest()
        if manifest is None:
            return self.findings

        command = [sys.executable, "-m", "pip_audit", "--format", "json", "--strict", "-r", str(manifest)]
        try:
            result = subprocess.run(
                command,
                cwd=self.source_root,
                capture_output=True,
                text=True,
                timeout=int(self.config.get("sca_timeout", 120)),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.add_finding(
                "SCA-001",
                "SCA",
                "Low",
                "Dependency audit could not be completed.",
                f"pip-audit unavailable or timed out: {exc}",
                "Install pip-audit in the scanner environment and retry the authorized assessment.",
                "A06:2021 Vulnerable and Outdated Components",
                cvss=0.0,
                confidence="high",
            )
            return self.findings

        try:
            vulnerabilities = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            self.add_finding(
                "SCA-002",
                "SCA",
                "Low",
                "Dependency audit returned an unreadable result.",
                result.stderr.strip()[:500] or "No JSON output was produced.",
                "Review the pip-audit version and rerun the scan.",
                "A06:2021 Vulnerable and Outdated Components",
                cvss=0.0,
                confidence="high",
            )
            return self.findings

        dependency_items = (
            vulnerabilities.get("dependencies", [])
            if isinstance(vulnerabilities, dict)
            else vulnerabilities
        )
        if not isinstance(dependency_items, list):
            dependency_items = []

        for item in dependency_items:
            if not isinstance(item, dict):
                continue
            vulnerabilities_for_item = item.get("vulns", [])
            if not isinstance(vulnerabilities_for_item, list):
                continue
            for vulnerability in vulnerabilities_for_item:
                if not isinstance(vulnerability, dict):
                    continue
                aliases = ", ".join(vulnerability.get("aliases", []))
                fix = ", ".join(vulnerability.get("fix_versions", [])) or "No fixed version reported"
                self.add_finding(
                    f"SCA-{vulnerability.get('id', 'UNKNOWN')}",
                    "SCA",
                    "High",
                    f"Known vulnerability in dependency {item.get('name', 'unknown')}.",
                    f"{vulnerability.get('id', 'unknown')}{' (' + aliases + ')' if aliases else ''}: "
                    f"{vulnerability.get('description', 'No description provided.')[:500]}",
                    f"Upgrade {item.get('name', 'the dependency')} to a patched version: {fix}.",
                    "A06:2021 Vulnerable and Outdated Components",
                    cvss=7.5,
                    confidence="high",
                    scanner="pip-audit",
                )
        return self.findings

    def _manifest(self) -> Path | None:
        configured = self.config.get("sca_requirements")
        if configured:
            candidate = (self.source_root / configured).resolve()
            if candidate.is_file() and self.source_root in candidate.parents:
                return candidate
        candidate = self.source_root / "requirements.txt"
        return candidate if candidate.is_file() else None
