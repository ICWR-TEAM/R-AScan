import requests, os
import secrets
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class LDAPInjectionScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.test_payload = "*"
        self.control_payload = f"rascan_user_{secrets.token_hex(4)}"
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def _ldap_error_signal(self, text):
        lowered = text.lower()
        indicators = [
            "invalid dn syntax",
            "ldapexception",
            "javax.naming",
            "operations error",
            "protocol error",
            "bad search filter",
        ]
        return next((item for item in indicators if item in lowered), None)

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        protocols = ["http", "https"]

        for proto in protocols:
            try:
                url = f"{proto}://{self.target}/login"
                data = {"username": self.test_payload, "password": "pass"}
                control = {"username": self.control_payload, "password": "pass"}
                control_response = requests.post(url, data=control, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                r = requests.post(url, data=data, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                control_signal = self._ldap_error_signal(control_response.text)
                signal = self._ldap_error_signal(r.text)

                if signal and signal != control_signal:
                    colored_status = self.printer.color_text("vulnerable", "red")
                    colored_payload = self.printer.color_text(self.test_payload, "yellow")
                    print(f"[*] [Module: {colored_module}] [Detected: LDAP Injection] [Payload: {colored_payload}] [URL: {url}]")
                    return {
                        "vulnerability": "LDAP Injection",
                        "payload": self.test_payload,
                        "status": "potential",
                        "potential": True,
                        "url": url,
                        "confidence": "low",
                        "signal": signal,
                        "note": "LDAP error differential observed; authenticated and schema-aware validation is required."
                    }

            except Exception as e:
                continue

        print(f"[*] [Module: {colored_module}] No LDAP Injection detected.")
        return {"vulnerability": "LDAP Injection", "status": "not detected"}

def scan(args=None):
    return LDAPInjectionScanner(args).run()
