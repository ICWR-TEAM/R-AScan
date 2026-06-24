import unittest

from r_ascan.core.target import Target


class TargetTests(unittest.TestCase):
    def test_hostname_and_custom_port(self):
        target = Target.parse("Example.COM", 8443, "/app")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.authority, "example.com:8443")
        self.assertEqual(target.url("https", "login"), "https://example.com:8443/app/login")

    def test_ipv4(self):
        target = Target.parse("192.0.2.10", "8080")
        self.assertEqual(target.base_url("http"), "http://192.0.2.10:8080")

    def test_ipv6_authority(self):
        target = Target.parse("2001:db8::1", 443)
        self.assertEqual(target.authority, "[2001:db8::1]:443")

    def test_rejects_url(self):
        with self.assertRaisesRegex(ValueError, "not a URL"):
            Target.parse("https://example.com")

    def test_rejects_embedded_port(self):
        with self.assertRaisesRegex(ValueError, "--port"):
            Target.parse("example.com:8080")

    def test_rejects_invalid_port(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            Target.parse("example.com", 70000)


if __name__ == "__main__":
    unittest.main()
