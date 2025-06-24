import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class LFIScanner:
    def __init__(self, target):
        self.target = target
        self.payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        results = []

        for payload in self.payloads:
            try:
                url = f"http://{self.target}/?file={payload}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if "root:x" in r.text:
                    colored_payload = self.printer.color_text(payload, "yellow")
                    print(f"[*] [Module: {colored_module}] [Detected: LFI] [Payload: {colored_payload}]")
                    results.append({"vulnerable": True, "payload": url})
                    break
            except Exception as e:
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
                results.append({"error": str(e)})

        if not results:
            print(f"[*] [Module: {colored_module}] No LFI detected.")
            results.append({"vulnerable": False})

        return results

def scan(args=None):
    return LFIScanner(args.target).scan()
