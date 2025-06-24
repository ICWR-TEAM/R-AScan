import os
import re
import requests
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other


class SQLiScanner:
    def __init__(self, args):
        self.target = args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "'--",
            '"--',
            "'#",
            "OR 1=1",
            "') OR ('1'='1",
        ]
        self.params = ["id", "q", "search", "user", "query"]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.error_patterns = [
            "you have an error in your sql syntax",
            "warning.*mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "mysql_fetch",
            "pg_query",
            "syntax error",
            "sqlstate",
        ]

    def is_sqli_error(self, text):
        lower_text = text.lower()
        return any(re.search(pat, lower_text) for pat in self.error_patterns)

    def check_payload(self, url, payload):
        try:
            resp = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            if self.is_sqli_error(resp.text):
                return {"url": url, "payload": payload, "type": "error-based"}
            elif payload in resp.text:
                return {"url": url, "payload": payload, "type": "reflected"}
            elif self.verbose:
                self.print_status("Not Vuln", url, level="-")
        except Exception as e:
            self.print_error(url, str(e))
        return None

    def print_status(self, status, url, level="*"):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        color = "green" if status.lower() == "vuln" else "red"
        status_colored = self.printer.color_text(f"{status}", color)
        print(f"[{level}] [Module: {colored_module}] [{status_colored}] {colored_url}")

    def print_error(self, url, error):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        colored_error = self.printer.color_text(str(error), "red")
        print(f"[!] [Module: {colored_module}] [Error] {colored_url} - {colored_error}")

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] Starting SQLi scan on {self.target}")

        tasks = []
        results = []
        schemes = ["http", "https"]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for scheme in schemes:
                for param in self.params:
                    for payload in self.payloads:
                        base_url = f"{scheme}://{self.target}"
                        full_url = f"{base_url}?{urlencode({param: payload})}"
                        tasks.append(executor.submit(self.check_payload, full_url, payload))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    self.print_status("Vuln", result["url"], level="+")
                    result["vulnerable"] = True
                    return result

        self.print_status("Not Vuln", "No SQLi detected")
        return {"vulnerable": False, "details": "No SQLi behavior detected"}

def scan(args=None):
    return SQLiScanner(args).run()
