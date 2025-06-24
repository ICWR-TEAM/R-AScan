import requests, os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class OpenRedirectScanner:
    def __init__(self):
        self.payloads = ["https://evil.com", "//evil.com"]
        self.protocols = ["http", "https"]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self, target):
        results = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for proto in self.protocols:
            for payload in self.payloads:
                url = f"{proto}://{target}/?redirect={payload}"
                try:
                    response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    if "Location" in response.headers and payload in response.headers["Location"]:
                        colored_payload = self.printer.color_text(payload, "yellow")
                        print(f"[*] [Module: {colored_module}] [Open Redirect Detected: {colored_payload}]")
                        results.append({
                            "vulnerable": True,
                            "protocol": proto,
                            "payload": url
                        })
                except Exception as e:
                    colored_error = self.printer.color_text(str(e), "red")
                    print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
                    results.append({
                        "error": str(e),
                        "protocol": proto,
                        "payload": url
                    })

        if not results:
            print(f"[*] [Module: {colored_module}] No open redirect detected.")
            results.append({"vulnerable": False})

        return results

def scan(args=None):
    return OpenRedirectScanner().scan(args.target)
