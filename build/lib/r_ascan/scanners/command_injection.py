import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other
from urllib.parse import urlencode

class CommandInjectionScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.threads = args.threads
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.payloads = [';echo cmd_injection_test_123', '&& echo cmd_injection_test_456', '| echo cmd_injection_test_789']
        self.unique_markers = ['cmd_injection_test_123', 'cmd_injection_test_456', 'cmd_injection_test_789']
        self.common_params = [
            "cmd", "exec", "execute", "input", "search", "query", "name", "id",
            "action", "data", "user", "file", "target", "url", "path", "page"
        ]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def print_status(self, level, status, url, param=None, marker=None):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        status_colored = self.printer.color_text(f"{status}", "green" if status == "Vuln" else "red")

        extra = ""
        if param:
            colored_param = self.printer.color_text(param, "magenta")
            extra += f"[param={colored_param}] "
        if marker:
            colored_marker = self.printer.color_text(marker, "green")
            extra += f"[marker={colored_marker}]"

        print(f"[{level}] [Module: {colored_module}] [{status_colored}] [{colored_url}] {extra}")

    def scan(self):
        results = []
        tasks = []
        schemes = ["https", "http"]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for scheme in schemes:
                base = f"{scheme}://{self.target}".rstrip("/")
                for param in self.common_params:
                    for i, payload in enumerate(self.payloads):
                        full_url = f"{base}/?{urlencode({param: payload})}"
                        tasks.append(executor.submit(self._test_payload, full_url, param, payload, self.unique_markers[i]))

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    results.append(res)

        if results:
            return {"vulnerability": "Command Injection", "vulnerable": True, "details": results}

        self.print_status("*", "Not Vuln", self.target)
        return {"vulnerability": "Command Injection", "vulnerable": False, "details": []}

    def _test_payload(self, url, param, payload, marker):
        try:
            r = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
            if r.status_code == 200 and marker in r.text and payload not in r.text:
                self.print_status("+", "Vuln", url, param, marker)
                return {
                    "parameter": param,
                    "payload": payload,
                    "marker_found": marker,
                    "url": url,
                    "status": r.status_code
                }
            elif self.verbose:
                self.print_status("-", "Not Vuln", url, param)
        except Exception as e:
            if self.verbose:
                colored_error = self.printer.color_text(str(e), "red")
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(url, "yellow")
                print(f"[!] [Module: {colored_module}] [Error] {colored_url} - {colored_error}")
        return None

def scan(args=None):
    return CommandInjectionScanner(args).scan()
