import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class CommandInjectionScanner:
    def __init__(self, args):
        self.target = args.target
        self.threads = args.threads
        self.verbose = args.verbose
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

    def scan(self):
        schemes = ["http", "https"]
        tasks = []
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for scheme in schemes:
                base = f"{scheme}://{self.target}"
                for param in self.common_params:
                    for i, payload in enumerate(self.payloads):
                        tasks.append(executor.submit(
                            self._send_request, base, param, payload, self.unique_markers[i]
                        ))

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    results.append(res)
                    self._print_result(res, vuln=True)

        if not results:
            self._print_result({"url": f"http://{self.target}"}, vuln=False)

        return {
            "vulnerability": "Command Injection",
            "status": "vulnerable" if results else "not detected",
            "details": results
        }

    def _send_request(self, base, param, payload, marker):
        try:
            url = f"{base}/?{param}={payload}"
            r = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
            if r.status_code == 200 and marker in r.text:
                return {
                    "parameter": param,
                    "payload": payload,
                    "marker_found": marker,
                    "url": url,
                    "status": r.status_code
                }
            elif self.verbose:
                self._print_result({"url": url}, vuln=False)
        except:
            pass
        return None

    def _print_result(self, res, vuln=False):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(res["url"], "yellow")
        status = "Vuln" if vuln else "Not Vuln"
        colored_status = self.printer.color_text(f"[{status}]", "green" if vuln else "red")
        print(f"[+] [Module: {colored_module}] {colored_status} [{res['url']}]")

def scan(args=None):
    return CommandInjectionScanner(args).scan()
