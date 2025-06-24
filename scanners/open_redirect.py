import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class OpenRedirectScanner:
    def __init__(self, args):
        self.target = args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.payloads = ["https://evil.com", "//evil.com"]
        self.protocols = ["http", "https"]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def print_status(self, level, status, url, extra=""):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        status_colored = self.printer.color_text(f"[{status}]", "green" if status == "Vuln" else "red")
        print(f"[{level}] [Module: {colored_module}] {status_colored} {colored_url} {extra}")

    def scan(self):
        results = []
        tasks = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for proto in self.protocols:
                base_url = f"{proto}://{self.target}"
                for payload in self.payloads:
                    url = f"{base_url}/?redirect={payload}"
                    tasks.append(executor.submit(self._check_redirect, proto, payload, url))

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    results.append(res)
                    if res.get("vulnerable"):
                        return {"vulnerable": True, "details": results}

        self.print_status("*", "Not Vuln", self.target)
        return {"vulnerable": False, "details": results}

    def _check_redirect(self, proto, payload, url):
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            location = response.headers.get("Location", "")
            if payload in location:
                self.print_status("+", "Vuln", url, f"→ {location}")
                return {
                    "vulnerable": True,
                    "protocol": proto,
                    "payload": url,
                    "redirect_to": location
                }
            elif self.verbose:
                self.print_status("-", "Not Vuln", url)
        except Exception as e:
            self.print_status("!", "Error", url, str(e))
            return {
                "error": str(e),
                "protocol": proto,
                "payload": url
            }
        return None

def scan(args=None):
    return OpenRedirectScanner(args).scan()
