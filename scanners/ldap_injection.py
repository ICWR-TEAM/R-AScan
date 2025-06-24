import requests, os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class LDAPInjectionScanner:
    def __init__(self, target):
        self.target = target
        self.test_payload = "*"
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        try:
            url = f"http://{self.target}/login"
            data = {"username": self.test_payload, "password": "pass"}
            r = requests.post(url, data=data, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)

            if "LDAP" in r.text or "Invalid DN" in r.text:
                colored_status = self.printer.color_text("vulnerable", "red")
                colored_payload = self.printer.color_text(self.test_payload, "yellow")
                print(f"[*] [Module: {colored_module}] [Detected: LDAP Injection] [Payload: {colored_payload}]")
                return {
                    "vulnerability": "LDAP Injection",
                    "payload": self.test_payload,
                    "status": "vulnerable"
                }

            print(f"[*] [Module: {colored_module}] No LDAP Injection detected.")
            return {"vulnerability": "LDAP Injection", "status": "not detected"}

        except Exception as e:
            colored_error = self.printer.color_text(str(e), "red")
            print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
            return {"error": str(e)}

def scan(args=None):
    return LDAPInjectionScanner(args.target).scan()
