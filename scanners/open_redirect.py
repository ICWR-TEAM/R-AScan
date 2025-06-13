import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class OpenRedirectScanner:
    def __init__(self):
        self.payloads = ["https://evil.com", "//evil.com"]

    def scan(self, target):
        results = []
        for payload in self.payloads:
            try:
                url = f"http://{target}/?redirect={payload}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if "Location" in response.headers and payload in response.headers["Location"]:
                    results.append({"vulnerable": True, "payload": url})
            except Exception as e:
                results.append({"error": str(e)})
        return results if results else [{"vulnerable": False}]

def scan(args=None):
    return OpenRedirectScanner().scan(args.target)
