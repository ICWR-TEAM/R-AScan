import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from concurrent.futures import ThreadPoolExecutor, as_completed

class AccessControlScanner:
    SENSITIVE_ENDPOINTS = [
        "/admin", "/admin/dashboard", "/admin/login",
        "/user/profile", "/user/settings",
        "/api/admin", "/api/private", "/api/user",
        "/config", "/.env", "/backup.zip",
    ]

    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.max_workers = args.threads

    def check_endpoint(self, protocol, endpoint):
        url = f"{protocol}://{self.target}{endpoint}"
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
        tasks = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for endpoint in self.SENSITIVE_ENDPOINTS:
                for protocol in ["http", "https"]:
                    tasks.append(executor.submit(self.check_endpoint, protocol, endpoint))

            for future in as_completed(tasks):
                results.append(future.result())

        return {"access_control_results": results}

def scan(args=None):
    scanner = AccessControlScanner(args)
    return scanner.scan()
