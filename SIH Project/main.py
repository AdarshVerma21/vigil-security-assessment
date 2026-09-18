"""CLI and web entry point for the WorldMonitor security assessment tool."""

import argparse
import os
from pathlib import Path
from typing import Any, Dict

import yaml
from flask import Flask, jsonify, render_template, request
from urllib.parse import urlsplit

from scanners.dast import DastScanner
from scanners.sast import SastScanner
from scanners.sca import ScaScanner
from scanners.rbac import RbacScanner
from scanners.idor import IdorScanner
from scanners.password_policy import PasswordPolicyScanner
from scanners.rate_limit import RateLimitScanner
from scanners.sqli import SqliScanner
from scanners.xss import XssScanner
from scanners.session_management import SessionManagementScanner
from scanners.api import ApiSecurityScanner
from scanners.data_privacy import DataPrivacyScanner
from report.html import write_html


BASE_DIR = Path(__file__).resolve().parent


def load_config(path: Path) -> Dict[str, Any]:
    """Load and validate the YAML configuration file."""
    with path.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    target_url = config.get("target_url")
    if not isinstance(target_url, str) or not target_url.strip():
        raise ValueError("Configuration must define a non-empty target_url")
    return config


def create_app(config_path: Path | None = None) -> Flask:
    """Create the production web application."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    configured_path = config_path or Path(
        os.environ.get("ASSESSMENT_CONFIG", BASE_DIR / "config/config.yaml")
    )
    app.extensions["scan_history"] = []

    @app.get("/")
    def dashboard() -> str:
        config = load_config(configured_path)
        return render_template(
            "dashboard.html",
            target_url=config["target_url"],
            endpoint_count=len(config.get("endpoints", [])),
            scanner_status="SAST + DAST + SCA online | API + RBAC + IDOR + session + XSS opt-in",
            findings=[],
        )

    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify({"status": "ok", "service": "worldmonitor-security-assessment"})

    @app.post("/api/scans")
    def start_scan() -> Any:
        config = load_config(configured_path)
        payload = request.get_json(silent=True) or {}
        mode = payload.get("mode", "both")
        if mode not in {"sast", "dast", "sca", "rbac", "idor", "password-policy", "rate-limit", "sqli", "session-management", "api-security", "data-privacy", "xss", "both", "all"}:
            return jsonify({"status": "error", "message": "mode must be sast, dast, sca, rbac, idor, password-policy, rate-limit, sqli, session-management, api-security, data-privacy, xss, both, or all"}), 400
        target_url = payload.get("target_url", config["target_url"])
        parsed_target = urlsplit(target_url) if isinstance(target_url, str) else None
        if (
            parsed_target is None
            or parsed_target.scheme not in {"http", "https"}
            or not parsed_target.netloc
        ):
            return jsonify({"status": "error", "message": "target_url must be an http or https URL"}), 400

        findings = []
        if mode in {"sast", "both", "all"}:
            findings.extend(SastScanner(BASE_DIR, target_url, config).scan())
        if mode in {"dast", "both"}:
            findings.extend(DastScanner(target_url, config).scan())
        if mode in {"sca", "all"}:
            findings.extend(ScaScanner(BASE_DIR, target_url, config).scan())
        if mode == "all":
            findings.extend(DastScanner(target_url, config).scan())
            findings.extend(RbacScanner(target_url, config).scan())
        if mode == "rbac":
            findings.extend(RbacScanner(target_url, config).scan())
        if mode == "idor":
            findings.extend(IdorScanner(target_url, config).scan())
        if mode == "all":
            findings.extend(IdorScanner(target_url, config).scan())
            findings.extend(PasswordPolicyScanner(target_url, config).scan())
        if mode == "password-policy":
            findings.extend(PasswordPolicyScanner(target_url, config).scan())
        if mode == "rate-limit":
            findings.extend(RateLimitScanner(target_url, config).scan())
        if mode == "sqli":
            findings.extend(SqliScanner(target_url, config).scan())
        if mode == "session-management":
            findings.extend(SessionManagementScanner(target_url, config).scan())
        if mode == "api-security":
            findings.extend(ApiSecurityScanner(target_url, config).scan())
        if mode == "data-privacy":
            findings.extend(DataPrivacyScanner(target_url, config).scan())
        if mode == "xss":
            findings.extend(XssScanner(target_url, config).scan())
        if mode == "all":
            findings.extend(RateLimitScanner(target_url, config).scan())
            findings.extend(SqliScanner(target_url, config).scan())
            findings.extend(SessionManagementScanner(target_url, config).scan())
            findings.extend(ApiSecurityScanner(target_url, config).scan())
            findings.extend(DataPrivacyScanner(target_url, config).scan())
            findings.extend(XssScanner(target_url, config).scan())
        result = {
            "status": "completed",
            "mode": mode,
            "finding_count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        }
        history = app.extensions["scan_history"]
        history.insert(0, result)
        del history[10:]
        return jsonify(
            {
                **result,
                "history": [
                    {"mode": item["mode"], "finding_count": item["finding_count"]}
                    for item in history
                ],
            }
        )

    @app.get("/api/scans")
    def scan_history() -> Any:
        return jsonify({"scans": app.extensions["scan_history"]})

    @app.after_request
    def add_security_headers(response: Any) -> Any:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:",
        )
        return response

    @app.errorhandler(ValueError)
    def handle_value_error(error: ValueError) -> Any:
        return jsonify({"status": "error", "message": str(error)}), 400

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run authorized WorldMonitor security checks."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/config.yaml"),
        help="Path to the YAML configuration file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/security-assessment.html"),
        help="Path for the generated HTML report.",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Run the local dashboard instead of generating a report.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.web:
        create_app(args.config).run(host=args.host, port=args.port)
        return 0

    config = load_config(args.config)
    findings = SastScanner(BASE_DIR, config["target_url"], config).scan()
    findings.extend(DastScanner(config["target_url"], config).scan())
    findings.extend(ScaScanner(BASE_DIR, config["target_url"], config).scan())
    findings.extend(RbacScanner(config["target_url"], config).scan())
    findings.extend(IdorScanner(config["target_url"], config).scan())
    findings.extend(PasswordPolicyScanner(config["target_url"], config).scan())
    findings.extend(RateLimitScanner(config["target_url"], config).scan())
    findings.extend(SqliScanner(config["target_url"], config).scan())
    findings.extend(SessionManagementScanner(config["target_url"], config).scan())
    findings.extend(ApiSecurityScanner(config["target_url"], config).scan())
    findings.extend(DataPrivacyScanner(config["target_url"], config).scan())
    findings.extend(XssScanner(config["target_url"], config).scan())
    write_html(findings, args.output)
    print(f"Assessment complete: {len(findings)} findings written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
