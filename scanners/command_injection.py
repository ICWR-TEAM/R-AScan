import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class CommandInjectionScanner:
    def __init__(self):
        self.payloads = [';id', '&& whoami', '| uname -a']
        self.common_params = [
            "cmd", "exec", "execute", "input", "search", "query", "name", "id",
            "action", "data", "user", "file", "target", "url", "path", "page"
        ]

    def scan(self, target):
        vulnerable = []
        for param in self.common_params:
            for payload in self.payloads:
                try:
                    url = f"http://{target}/?{param}={payload}"
                    r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                    if "uid=" in r.text or "Linux" in r.text or "root" in r.text:
                        vulnerable.append({
                            "parameter": param,
                            "payload": payload,
                            "status": "vulnerable"
                        })
                except:
                    continue

        if vulnerable:
            return {"vulnerability": "Command Injection", "status": "vulnerable", "details": vulnerable}
        return {"vulnerability": "Command Injection", "status": "not detected"}

def scan(args=None):
    return CommandInjectionScanner().scan(args.target)
