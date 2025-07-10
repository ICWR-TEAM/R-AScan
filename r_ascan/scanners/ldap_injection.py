import requests, os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class LDAPInjectionScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.test_payload = "*"
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        protocols = ["http", "https"]

        for proto in protocols:
            try:
                url = f"{proto}://{self.target}/login"
                data = {"username": self.test_payload, "password": "pass"}
                r = requests.post(url, data=data, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)

                if "LDAP" in r.text or "Invalid DN" in r.text:
                    colored_status = self.printer.color_text("vulnerable", "red")
                    colored_payload = self.printer.color_text(self.test_payload, "yellow")
                    print(f"[*] [Module: {colored_module}] [Detected: LDAP Injection] [Payload: {colored_payload}] [URL: {url}]")
                    return {
                        "vulnerability": "LDAP Injection",
                        "payload": self.test_payload,
                        "status": "vulnerable",
                        "url": url
                    }

            except Exception as e:
                continue

        print(f"[*] [Module: {colored_module}] No LDAP Injection detected.")
        return {"vulnerability": "LDAP Injection", "status": "not detected"}

def scan(args=None):
    return LDAPInjectionScanner(args).run()
