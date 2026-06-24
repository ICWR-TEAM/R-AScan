import os
import secrets
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class SSRFScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.marker = secrets.token_hex(6)
        self.payloads = [
            f"http://127.0.0.1/?r_ascan={self.marker}",
            f"http://localhost/?r_ascan={self.marker}",
        ]
        self.params = ["url", "next", "redirect", "dest", "target"]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def print_status(self, level, status, url):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        color = "green" if status == "Vuln" else "red"
        status_colored = self.printer.color_text(f"{status}", color)
        print(f"[{level}] [Module: {colored_module}] [{status_colored}] {colored_url}")

    def print_error(self, url, error):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        colored_error = self.printer.color_text(str(error), "red")
        print(f"[!] [Module: {colored_module}] [Error] {colored_url} - {colored_error}")

    def check_payload(self, full_url):
        try:
            r = requests.get(full_url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            # A reflected URL is not proof of a server-side request. Without an
            # out-of-band callback, only report a potential signal when content
            # characteristic of a loopback service appears without our canary.
            text = r.text.lower()
            reflected = self.marker in text
            signatures = ("connection refused", "localhost", "127.0.0.1")
            if not reflected and any(value in text for value in signatures):
                return {"url": full_url, "confidence": "low", "status": "potential"}
            if self.verbose:
                self.print_status("-", "Not Vuln", full_url)
        except Exception as e:
            if self.verbose:
                self.print_error(full_url, e)
        return None

    def run(self):
        tasks = []
        results = []
        schemes = ["http", "https"]
        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] Starting SSRF scan on {self.target}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for scheme in schemes:
                for param in self.params:
                    for payload in self.payloads:
                        base = f"{scheme}://{self.target}"
                        full_url = f"{base}/?{param}={payload}"
                        tasks.append(executor.submit(self.check_payload, full_url))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    self.print_status("+", "Potential", result["url"])
                    return [{"vulnerable": False, **result}]

        self.print_status("*", "Not Vuln", "No SSRF detected")
        return [{"vulnerable": False, "details": "No non-reflection SSRF signal detected"}]

def scan(args=None):
    return SSRFScanner(args).run()
