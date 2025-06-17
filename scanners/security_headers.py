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
            response = self._get_response(target)
            return self._check_headers(response)
        except Exception as e:
            return {"error": str(e)}

    def _get_response(self, target):
        for scheme in ["https://", "http://"]:
            try:
                url = f"{scheme}{target}"
                res = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                res.raise_for_status()
                return res
            except requests.RequestException:
                continue
        raise Exception("Cannot access target.")

    def _check_headers(self, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        found = {h: headers[h.lower()] for h in self.required_headers if h.lower() in headers}
        missing = [h for h in self.required_headers if h.lower() not in headers]
        return {
            "found": found,
            "missing": missing,
            "score": f"{len(found)}/{len(self.required_headers)}"
        }

def scan(args=None):
    return SecurityHeaderScanner().scan(args.target)
