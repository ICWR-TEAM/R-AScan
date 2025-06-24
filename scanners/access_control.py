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
        self.max_workers = args.threads

    def check_endpoint(self, protocol, endpoint):
        url = f"{protocol}://{self.target}{endpoint}"
        module_name = os.path.basename(__file__)
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            result = {
                "url": url,
                "status_code": r.status_code,
                "content_length": len(r.content),
                "redirect_location": r.headers.get("Location", None),
            }
            
            colored_module = self.utils.color_text(module_name, "cyan")
            colored_url = self.utils.color_text(result["url"], "yellow")
            colored_status = self.utils.color_text(str(result["status_code"]), "green")
            colored_redirect = self.utils.color_text(str(result["redirect_location"]), "magenta")
            
            print(f"[+] [Module: {colored_module}] [URL: {colored_url}] [Status Code: {colored_status}] [Redirect: {colored_redirect}]")

            return result
        except Exception as e:
            print(f"[-] [Module: {module_name}] [Error: {e}]")
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
