import requests, os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class RCEScanner:
    def __init__(self):
        self.payloads = {
            ';echo rce_test_123': 'rce_test_123',
            '|echo rce_test_456': 'rce_test_456',
            '`echo rce_test_789`': 'rce_test_789'
        }
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self, target):
        results = []
        schemes = ["https", "http"]
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for scheme in schemes:
            for payload, marker in self.payloads.items():
                try:
                    url = f"{scheme}://{target}/?cmd={payload}"
                    response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                    if response.status_code == 200 and marker in response.text:
                        colored_payload = self.printer.color_text(payload, "yellow")
                        print(f"[*] [Module: {colored_module}] [RCE Detected: {colored_payload}]")
                        results.append({"vulnerable": True, "payload": url, "marker": marker})
                        return results
                except requests.RequestException as e:
                    colored_error = self.printer.color_text(str(e), "red")
                    print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
                    results.append({"error": str(e)})
            if results and any(r.get("vulnerable") for r in results):
                break

        if not results:
            print(f"[*] [Module: {colored_module}] No RCE vulnerability detected.")
            results.append({"vulnerable": False})

        return results

def scan(args=None):
    return RCEScanner().scan(args.target)
