"""HTML report generation."""

from collections import defaultdict
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, select_autoescape

from core.models import Finding


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WorldMonitor Security Assessment</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    section { margin-bottom: 2rem; }
    article { border: 1px solid #ddd; margin: 1rem 0; padding: 1rem; }
    code, pre { white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>WorldMonitor Security Assessment</h1>
  {% for severity, category_groups in grouped.items() %}
  <section>
    <h2>{{ severity }}</h2>
    {% for category, findings in category_groups.items() %}
    <h3>{{ category }} ({{ findings|length }})</h3>
    {% for finding in findings %}
    <article>
      <h4>{{ finding.id }}: {{ finding.title }}</h4>
      <p><strong>Description:</strong> {{ finding.description }}</p>
      <p><strong>Affected component/endpoint:</strong> {{ finding.affected_component }}</p>
      <p><strong>Business impact:</strong> {{ finding.business_impact }}</p>
      <p><strong>Steps to reproduce:</strong></p>
      <ol>{% for step in finding.steps_to_reproduce %}<li>{{ step }}</li>{% endfor %}</ol>
      <p><strong>Proof-of-concept artifact:</strong>
        <code>{{ finding.poc_evidence.artifact_ref }}</code>
        — {{ finding.poc_evidence.description }}</p>
      <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
      <p><strong>OWASP:</strong> {{ finding.owasp_mapping }}</p>
      <p><strong>CVSS:</strong> {{ finding.cvss if finding.cvss is not none else "Not scored" }}
      · <strong>Vector:</strong> {{ finding.cvss_vector }}
      · <strong>Confidence:</strong> {{ finding.confidence }}
      · <strong>Scanner:</strong> {{ finding.scanner }}</p>
    </article>
    {% endfor %}
    {% endfor %}
  </section>
  {% endfor %}
</body>
</html>
"""


def render_html(findings: Iterable[Finding]) -> str:
    """Render findings grouped by severity."""
    grouped = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        grouped[finding.severity.title()][finding.category].append(finding)

    environment = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = environment.from_string(_TEMPLATE)
    order = ("Critical", "High", "Medium", "Low", "Informational")
    ordered_groups = {
        severity: grouped[severity] for severity in order if grouped[severity]
    }
    return template.render(grouped=ordered_groups)


def write_html(findings: Iterable[Finding], output_path: Path) -> None:
    """Write an HTML report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(findings), encoding="utf-8")
