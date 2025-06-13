import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class SecurityHeaderScanner:
    def __init__(self):
        self.required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]

    def scan(self, target):
        try:
            url = f"http://{target}"
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            headers = response.headers

            found = {h: headers[h] for h in self.required_headers if h in headers}
            missing = [h for h in self.required_headers if h not in headers]

            return {
                "found": found,
                "missing": missing,
                "score": f"{len(found)}/{len(self.required_headers)}"
            }
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return SecurityHeaderScanner().scan(args.target)
