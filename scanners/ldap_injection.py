import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class LDAPInjectionScanner:
    def __init__(self):
        self.test_payload = "*"

    def scan(self, target):
        try:
            url = f"http://{target}/login"
            data = {"username": self.test_payload, "password": "pass"}
            r = requests.post(url, data=data, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            if "LDAP" in r.text or "Invalid DN" in r.text:
                return {"vulnerability": "LDAP Injection", "payload": self.test_payload, "status": "vulnerable"}
        except:
            pass
        return {"vulnerability": "LDAP Injection", "status": "not detected"}

def scan(args=None):
    return LDAPInjectionScanner().scan(args.target)
