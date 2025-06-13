import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class SSRFScanner:
    def __init__(self):
        self.payloads = ["http://127.0.0.1", "http://localhost"]

    def scan(self, target):
        results = []
        for payload in self.payloads:
            try:
                url = f"http://{target}/?url={payload}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if "localhost" in response.text or "127.0.0.1" in response.text:
                    results.append({"vulnerable": True, "payload": url})
            except Exception as e:
                results.append({"error": str(e)})
        return results if results else [{"vulnerable": False}]

def scan(args=None):
    return SSRFScanner().scan(args.target)
