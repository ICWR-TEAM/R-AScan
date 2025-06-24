import requests, os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class SSRFScanner:
    def __init__(self):
        self.payloads = ["http://127.0.0.1", "http://localhost"]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self, target):
        results = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for payload in self.payloads:
            try:
                url = f"http://{target}/?url={payload}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if "localhost" in response.text or "127.0.0.1" in response.text:
                    colored_payload = self.printer.color_text(payload, "yellow")
                    print(f"[*] [Module: {colored_module}] SSRF Detected with payload: {colored_payload}")
                    results.append({"vulnerable": True, "payload": url})
            except Exception as e:
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
                results.append({"error": str(e)})

        if not results:
            print(f"[*] [Module: {colored_module}] No SSRF detected.")
        return results if results else [{"vulnerable": False}]

def scan(args=None):
    return SSRFScanner().scan(args.target)
