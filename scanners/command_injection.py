import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class CommandInjectionScanner:
    def __init__(self):
        self.payloads = [';echo cmd_injection_test_123', '&& echo cmd_injection_test_456', '| echo cmd_injection_test_789']
        self.unique_markers = ['cmd_injection_test_123', 'cmd_injection_test_456', 'cmd_injection_test_789']
        self.common_params = [
            "cmd", "exec", "execute", "input", "search", "query", "name", "id",
            "action", "data", "user", "file", "target", "url", "path", "page"
        ]

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
        return {"vulnerability": "Command Injection", "status": "not detected"}

def scan(args=None):
    return CommandInjectionScanner().scan(args.target)
