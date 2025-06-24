import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class CommandInjectionScanner:
    def __init__(self, args):
        self.target = args.target
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

    def print_status(self, level, status, url, extra=""):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        status_colored = self.printer.color_text(f"[{status}]", "green" if status == "Vuln" else "red")
        print(f"[{level}] [Module: {colored_module}] {status_colored} [{colored_url}] {extra}")

    def scan(self):
        results = []
        schemes = ["https", "http"]

        for scheme in schemes:
            base = f"{scheme}://{self.target}".rstrip("/")
            for param in self.common_params:
                for i, payload in enumerate(self.payloads):
                    try:
                        url = f"{base}/?{param}={payload}"
                        response = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
                        if response.status_code == 200 and self.unique_markers[i] in response.text:
                            self.print_status("+", "Vuln", url, f"param={param} marker={self.unique_markers[i]}")
                            results.append({
                                "parameter": param,
                                "payload": payload,
                                "marker_found": self.unique_markers[i],
                                "url": url,
                                "status": response.status_code
                            })
                        elif self.verbose:
                            self.print_status("-", "Not Vuln", url)
                    except Exception as e:
                        if self.verbose:
                            colored_error = self.printer.color_text(str(e), "red")
                            colored_module = self.printer.color_text(self.module_name, "cyan")
                            colored_url = self.printer.color_text(url, "yellow")
                            print(f"[!] [Module: {colored_module}] [Error] {colored_url} - {colored_error}")
                        continue

            if results:
                break  # Stop after first scheme (http or https) if vuln found

        if results:
            return {"vulnerability": "Command Injection", "vulnerable": True, "details": results}

        self.print_status("*", "Not Vuln", self.target)
        return {"vulnerability": "Command Injection", "vulnerable": False, "details": []}

def scan(args=None):
    return CommandInjectionScanner(args).scan()
