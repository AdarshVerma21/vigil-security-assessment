import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from scanners.api import ApiSecurityScanner
from scanners.idor import IdorScanner
from scanners.password_policy import PasswordPolicyScanner
from scanners.rate_limit import RateLimitScanner
from scanners.rbac import RbacScanner
from scanners.session_management import SessionManagementScanner
from scanners.sqli import SqliScanner
from scanners.xss import XssScanner


class MockTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *_args):
        return


class ActiveModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockTargetHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_port}"
        cls.artifact_dir = Path(__file__).parent / "_artifacts"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        for artifact in cls.artifact_dir.glob("*"):
            artifact.unlink()
        if cls.artifact_dir.exists():
            cls.artifact_dir.rmdir()

    def test_active_modules_skip_out_of_scope(self):
        modules = (
            (RbacScanner, "rbac"),
            (IdorScanner, "idor"),
            (PasswordPolicyScanner, "password_policy"),
            (RateLimitScanner, "rate_limit"),
            (SqliScanner, "sqli"),
            (SessionManagementScanner, "session_management"),
            (ApiSecurityScanner, "api_security"),
            (XssScanner, "xss"),
        )
        for scanner_class, section in modules:
            with self.subTest(section=section):
                scanner = scanner_class(
                    self.target,
                    {
                        "evidence_dir": str(self.artifact_dir),
                        section: {"enabled": True, "scope": ["https://not-authorized.invalid"]},
                    },
                )
                with patch.object(scanner, "request", side_effect=AssertionError("out-of-scope request")):
                    self.assertEqual(scanner.scan(), [])

    def test_each_active_module_accepts_scoped_mock_target(self):
        configs = [
            (RbacScanner, "rbac", {"enabled": True, "scope": [self.target], "endpoints": []}),
            (IdorScanner, "idor", {"enabled": True, "scope": [self.target], "endpoints": []}),
            (
                PasswordPolicyScanner,
                "password_policy",
                {"enabled": True, "scope": [self.target], "registration": {"enabled": False}},
            ),
            (
                RateLimitScanner,
                "rate_limit",
                {
                    "enabled": True,
                    "scope": [self.target],
                    "count": 1,
                    "cooldown_seconds": 0,
                    "endpoints": [{"path": "/", "method": "GET", "format": "json"}],
                },
            ),
            (
                SqliScanner,
                "sqli",
                {
                    "enabled": True,
                    "scope": [self.target],
                    "endpoints": [{"path": "/", "method": "GET", "inputs": []}],
                },
            ),
            (
                SessionManagementScanner,
                "session_management",
                {"enabled": True, "scope": [self.target], "accounts": []},
            ),
            (
                ApiSecurityScanner,
                "api_security",
                {"enabled": True, "scope": [self.target], "endpoints": []},
            ),
            (
                XssScanner,
                "xss",
                {"enabled": True, "scope": [self.target], "endpoints": []},
            ),
        ]
        for scanner_class, section, settings in configs:
            with self.subTest(section=section):
                findings = scanner_class(
                    self.target,
                    {"evidence_dir": str(self.artifact_dir), section: settings},
                ).scan()
                self.assertIsInstance(findings, list)

        artifacts = list(self.artifact_dir.glob("*.json"))
        self.assertTrue(artifacts)
        exchange = json.loads(artifacts[0].read_text(encoding="utf-8"))
        self.assertIn("request", exchange)
        self.assertIn("response", exchange)


if __name__ == "__main__":
    unittest.main()
