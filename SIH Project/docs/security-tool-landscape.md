# VIGIL security tool landscape

This brief records the external capabilities VIGIL is designed to complement. It
is intentionally focused on official documentation and project repositories. Tool
availability and licensing can change, so verify before shipping a production
integration.

## DAST

| Tool | Detection focus | Automation/output | License |
|---|---|---|---|
| OWASP ZAP | Passive and active web scanning, spiders, authentication, API access | REST API; JSON, XML, HTML and other report formats | Apache-2.0 |
| Nuclei | Template-based web, network and cloud misconfiguration checks | CLI/CI; JSONL, JSON, Markdown and SARIF integrations | MIT |
| Nikto | Web-server files, dangerous defaults and outdated server software | CLI; text, XML, CSV, JSON and HTML output | GPL-2.0 |
| w3af | Web application audit plugins for discovery and vulnerability checks | CLI and scripting; text/console and result exports | GPL-2.0 |
| Arachni | Web application audit and browser-like crawling | REST API and CLI; JSON/XML/HTML reports | Arachni license (review before redistribution) |

## SAST

| Tool | Languages | Automation/reporting | License |
|---|---|---|---|
| Semgrep | Multi-language, rule-driven analysis | `semgrep scan`/CI; JSON, SARIF, JUnit and GitLab formats | LGPL-2.1 |
| Bandit | Python | CLI/CI; JSON, SARIF, CSV, HTML and screen output | Apache-2.0 |
| ESLint security plugins | JavaScript/TypeScript | CLI/CI; JSON, stylish and machine-readable formatters | ESLint MIT; plugins vary |
| SonarQube Community Build | Many languages | Server/CI scanners and quality gates; web dashboard and APIs | LGPL-3.0 for Community Build (edition terms vary) |
| Horusec | Multi-language | CLI/CI; JSON, SARIF, Sonar and other formats | Apache-2.0 |

## SCA and vulnerability management

| Tool | Coverage and integration | Dashboard/API | License or pricing |
|---|---|---|---|
| pip-audit | Python package vulnerabilities from PyPI/advisory sources | CLI; JSON and other formats, CI-friendly | Apache-2.0 |
| npm audit | npm dependency advisories and remediation metadata | npm CLI; JSON and human output | npm CLI license |
| Trivy | OS packages, language dependencies, images, IaC and secrets | CLI/server; JSON, SARIF, CycloneDX and table output | Apache-2.0 |
| OWASP Dependency-Check | Dependency identifiers and known CVEs, especially JVM/.NET ecosystems | CLI/plugin; XML, JSON, HTML, CSV and SARIF | Apache-2.0 |
| DefectDojo | Imports and normalizes SAST/DAST/SCA reports, deduplicates and tracks remediation | Web dashboard and REST API | BSD-3-Clause community project |
| Faraday | Collaborative vulnerability management and report aggregation | Web UI/API with workspace and issue tracking | GPL-3.0 |
| Greenbone/OpenVAS | Network and infrastructure vulnerability assessment | Web UI and management protocol/API | GPL-2.0 components; appliance offerings vary |

## API-focused products

42Crunch emphasizes OpenAPI contract auditing, API fuzzing and runtime protection.
StackHawk combines API/web DAST with CI workflows and business-logic testing.
Astra's API scanner focuses on endpoint discovery and common API issues such as
authentication, authorization and input validation. These products are useful
reference points for VIGIL's future authorized BOLA/IDOR and role-boundary
workflows; those checks remain opt-in until test accounts and endpoint contracts
are configured.

## Comparison and gap analysis

| Tool family | Open source | Dashboard | Automation API | Best fit |
|---|---:|---:|---:|---|
| ZAP | Yes | Yes | Yes | Broad web DAST |
| Semgrep/Bandit | Yes | Limited | CLI/CI | Fast developer SAST |
| Trivy/pip-audit | Yes | Limited | CLI/CI | Dependency and image SCA |
| DefectDojo/Faraday | Yes | Yes | Yes | Aggregation and remediation |
| VIGIL | Yes (project code) | Yes | HTTP API | Lightweight, authorized SAST+DAST+SCA demo |

The recurring free/open-source gaps are setup complexity, fragmented outputs,
inconsistent severity normalization, limited scan history/trend views, and
little guidance for safe authenticated API/RBAC workflows. VIGIL now addresses
the first dashboard-level slice of this gap with a unified finding model, CVSS
and confidence metadata, SCA ingestion, and in-process scan history. Persistent
multi-user history, worker queues, external scanner adapters, and opt-in
authenticated testing are still roadmap items.

## Sources

- OWASP ZAP API documentation: https://www.zaproxy.org/docs/api/
- Semgrep CLI reference: https://docs.semgrep.dev/cli-reference
- Bandit repository: https://github.com/PyCQA/bandit
- Trivy repository: https://github.com/aquasecurity/trivy
- OWASP Dependency-Check: https://github.com/jeremylong/DependencyCheck
- DefectDojo repository: https://github.com/DefectDojo/django-DefectDojo
- Faraday repository: https://github.com/infobyte/faraday
- Greenbone Community Edition: https://github.com/greenbone/openvas-scanner
- pip-audit documentation: https://github.com/pypa/pip-audit
- AI-Vulnerability-Orchestrator prior-art project: https://github.com/L11cif3r/AI-Vulnerability-Orchestrator
- OpenAnt research project: https://arxiv.org/abs/2606.19149
