import requests, os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from concurrent.futures import ThreadPoolExecutor, as_completed
from module.other import Other

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
        self.verbose = args.verbose
        self.max_workers = args.threads
        self.printer = Other()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]

    def check_endpoint(self, protocol, endpoint):
        url = f"{protocol}://{self.target}{endpoint}"
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            status_code = r.status_code
            redirect = r.headers.get("Location", None)
            result = {
                "url": url,
                "status_code": status_code,
                "content_length": len(r.content),
                "redirect_location": redirect,
            }

            is_vuln = status_code in [200, 201, 202, 204]
            if self.verbose or is_vuln:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(url, "yellow")
                colored_status = self.printer.color_text(str(status_code), "green" if is_vuln else "red")
                colored_redirect = self.printer.color_text(str(redirect), "magenta")
                print(f"[+] [Module: {colored_module}] [URL: {colored_url}] [Status Code: {colored_status}] [Redirect: {colored_redirect}]")

            return result

        except Exception as e:
            if self.verbose:
                print(f"[-] [Module: {self.module_name}] [Error: {e}]")
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
