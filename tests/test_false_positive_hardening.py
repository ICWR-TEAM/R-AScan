import unittest
from types import SimpleNamespace

from r_ascan.scanners.broken_access_control import BrokenAccessControlScanner
from r_ascan.scanners.http_smuggler import HTTPSmugglingScanner
from r_ascan.scanners.ldap_injection import LDAPInjectionScanner
from r_ascan.scanners.top_25_owasp_full_scanner import Top25FastScanner
from r_ascan.scanners.xss import XSSScanner


def args(**overrides):
    values = {"target": "example.com", "port": None, "threads": 1, "verbose": False, "path": "/"}
    values.update(overrides)
    return SimpleNamespace(**values)


class FalsePositiveHardeningTests(unittest.TestCase):
    def test_xss_reflection_classification_requires_executable_context(self):
        scanner = XSSScanner(args())
        escaped = scanner._classify_reflection(f"&lt;svg data-rascan=&quot;{scanner.marker}&quot;&gt;")
        executable = scanner._classify_reflection(
            f'<svg data-rascan="{scanner.marker}" onload=alert(1)>'
        )

        self.assertEqual(escaped["status"], "potential")
        self.assertEqual(executable["status"], "confirmed")

    def test_dom_xss_requires_source_and_sink(self):
        scanner = XSSScanner(args())

        self.assertFalse(scanner._has_dom_xss_sink("element.innerHTML = 'static'"))
        self.assertTrue(scanner._has_dom_xss_sink("element.innerHTML = location.hash"))
        self.assertFalse(scanner._has_dom_xss_sink("element.textContent = location.hash"))

    def test_http_smuggling_keyword_only_response_is_not_an_anomaly(self):
        scanner = HTTPSmugglingScanner(args())

        valid, reason = scanner.strict_validation("HTTP/1.1 200 OK\r\n\r\nsecret admin")

        self.assertFalse(valid)
        self.assertEqual(reason, "no desync-specific response pattern")

    def test_http_smuggling_requires_probe_specific_secondary_response(self):
        scanner = HTTPSmugglingScanner(args())
        probe = "HTTP/1.1 400 Bad Request\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
        control = "HTTP/1.1 200 OK\r\n\r\n"

        valid, reason = scanner.strict_validation(probe, control)

        self.assertTrue(valid)
        self.assertIn("probe only", reason)

    def test_top25_lfi_requires_passwd_like_structure(self):
        scanner = Top25FastScanner(args())

        self.assertFalse(scanner._looks_like_passwd("root:x:0:0:/bin/bash"))
        self.assertTrue(scanner._looks_like_passwd(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        ))

    def test_broken_access_control_ignores_login_denials(self):
        scanner = BrokenAccessControlScanner.__new__(BrokenAccessControlScanner)

        self.assertFalse(scanner._looks_like_accessible_resource(
            200,
            "<html>Please sign in to continue</html>",
            {"Content-Type": "text/html"},
        ))
        self.assertTrue(scanner._looks_like_accessible_resource(
            200,
            '{"admin": true}',
            {"Content-Type": "application/json"},
        ))

    def test_ldap_signal_uses_specific_errors(self):
        scanner = LDAPInjectionScanner(args())

        self.assertIsNone(scanner._ldap_error_signal("LDAP enabled"))
        self.assertEqual(scanner._ldap_error_signal("Invalid DN Syntax"), "invalid dn syntax")


if __name__ == "__main__":
    unittest.main()
