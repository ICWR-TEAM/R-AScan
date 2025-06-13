import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class AccessControlScanner:
    SENSITIVE_ENDPOINTS = [
        "/admin", "/admin/dashboard", "/admin/login",
        "/user/profile", "/user/settings",
        "/api/admin", "/api/private", "/api/user",
        "/config", "/.env", "/backup.zip",
    ]

    def __init__(self, target):
        self.target = target

    def check_endpoint(self, endpoint):
        url = f"http://{self.target}{endpoint}"
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            return {
                "url": url,
                "status_code": r.status_code,
                "content_length": len(r.content),
                "redirect_location": r.headers.get("Location", None),
            }
        except Exception as e:
            return {"url": url, "error": str(e)}

    def scan(self):
        results = []
        for endpoint in self.SENSITIVE_ENDPOINTS:
            result = self.check_endpoint(endpoint)
            results.append(result)
        return {"access_control_results": results}

def scan(args=None):
    scanner = AccessControlScanner(args.target)
    return scanner.scan()
