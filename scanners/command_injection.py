import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class CommandInjectionScanner:
    def __init__(self):
        self.payloads = [';echo cmd_injection_test_123', '&& echo cmd_injection_test_456', '| echo cmd_injection_test_789']
        self.unique_markers = ['cmd_injection_test_123', 'cmd_injection_test_456', 'cmd_injection_test_789']
        self.common_params = [
            "cmd", "exec", "execute", "input", "search", "query", "name", "id",
            "action", "data", "user", "file", "target", "url", "path", "page"
        ]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self, target):
        vulnerable = []
        schemes = ["https", "http"]

        for scheme in schemes:
            for param in self.common_params:
                for i, payload in enumerate(self.payloads):
                    try:
                        url = f"{scheme}://{target}/?{param}={payload}"
                        r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                        if r.status_code == 200 and self.unique_markers[i] in r.text:
                            colored_module = self.printer.color_text(self.module_name, "cyan")
                            colored_param = self.printer.color_text(param, "magenta")
                            colored_marker = self.printer.color_text(self.unique_markers[i], "green")
                            colored_url = self.printer.color_text(url, "yellow")
                            print(f"[*] [Module: {colored_module}] [Param: {colored_param}] [Marker: {colored_marker}] [URL: {colored_url}]")

                            vulnerable.append({
                                "parameter": param,
                                "payload": payload,
                                "marker_found": self.unique_markers[i],
                                "url": url,
                                "status": "vulnerable"
                            })
                    except requests.RequestException:
                        continue

            if vulnerable:
                break

        if vulnerable:
            return {"vulnerability": "Command Injection", "status": "vulnerable", "details": vulnerable}

        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] No command injection detected.")
        return {"vulnerability": "Command Injection", "status": "not detected"}

def scan(args=None):
    return CommandInjectionScanner().scan(args.target)
