import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class OpenRedirectScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.payloads = ["https://evil.com", "//evil.com"]
        self.protocols = ["http", "https"]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def print_status(self, level, status, url_info):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        status_colored = self.printer.color_text(f"[{status}]", "green" if status == "Vuln" else "red")
        url_colored = self.printer.color_text(f"{url_info}", "yellow")
        print(f"[{level}] [Module: {colored_module}] [{status_colored}] {url_colored}")

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

        return {
            "vulnerable": any(r.get("vulnerable") for r in results),
            "details": results
        }

    def _check_redirect(self, proto, payload, url):
        try:
            response = requests.get(
                url,
                headers=HTTP_HEADERS,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=False
            )

            location = response.headers.get("Location", "")
            status_code = response.status_code

            if (
                status_code in [301, 302, 303, 307, 308] and
                self._is_strict_match(location, payload)
            ):
                self.print_status("+", "Vuln", f"{url} -> {location}")
                return {
                    "vulnerable": True,
                    "protocol": proto,
                    "payload": url,
                    "redirect_to": location
                }

            if self.verbose:
                self.print_status("-", "Not Vuln", url)

            return {
                "vulnerable": False,
                "protocol": proto,
                "payload": url
            }

        except Exception as e:
            if self.verbose:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(url, "yellow")
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error] {colored_url} - {colored_error}")
            return {
                "error": str(e),
                "protocol": proto,
                "payload": url
            }

    def _is_strict_match(self, location, expected_payload):
        if not location:
            return False
        parsed = urlparse(location)
        return (
            location.strip() == expected_payload or
            parsed.netloc.lower() == "evil.com" and parsed.scheme in ["http", "https"]
        )

def scan(args=None):
    return OpenRedirectScanner(args).scan()
