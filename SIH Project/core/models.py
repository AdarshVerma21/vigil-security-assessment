"""Data models shared by security scanners."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass
class Finding:
    """A single detection produced by a scanner."""

    id: str
    category: str
    severity: str
    description: str
    evidence: str
    remediation: str
    owasp_mapping: str
    cvss: float | None = None
    confidence: str = "medium"
    scanner: str = "vigil"
    title: str = ""
    affected_component: str = ""
    cvss_vector: str = ""
    steps_to_reproduce: List[str] | None = None
    poc_evidence: Dict[str, Any] | None = None
    business_impact: str = ""

    def __post_init__(self) -> None:
        """Guarantee the report schema for legacy scanner call sites."""
        self.title = self.title or self.description
        self.affected_component = self.affected_component or self.category
        self.cvss_vector = self.cvss_vector or self._default_cvss_vector()
        self.steps_to_reproduce = self.steps_to_reproduce or [
            f"1. Run the {self.scanner} scanner against the configured target.",
            f"2. Review the affected component: {self.affected_component}.",
            "3. Confirm the redacted proof-of-concept artifact and observed behavior.",
        ]
        self.poc_evidence = self.poc_evidence or {
            "artifact_ref": f"finding://{self.id}/evidence",
            "description": "Redacted proof-of-concept evidence is available in the finding artifact.",
        }
        self.business_impact = self.business_impact or self._default_business_impact()

    def _default_cvss_vector(self) -> str:
        score = self.cvss if self.cvss is not None else 0.0
        if score >= 9.0:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        if score >= 7.0:
            return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
        if score >= 4.0:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

    def _default_business_impact(self) -> str:
        return (
            f"The issue may affect the confidentiality, integrity, or availability "
            f"of the {self.affected_component}."
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a serializable representation for reports and integrations."""
        return asdict(self)
