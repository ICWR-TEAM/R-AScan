import os
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class SQLiScanner:
    COMMON_PARAMS = ["id", "q", "search", "user", "query", "page", "lang", "ref", "file", "name"]

    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
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
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.error_patterns = [
            r"you have an error in your sql syntax",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"mysql_fetch",
            r"pg_query",
            r"syntax error",
            r"sqlstate",
        ]

    def is_sqli_error(self, text):
        lower_text = text.lower()
        return any(re.search(pat, lower_text) for pat in self.error_patterns)

    def extract_params_from_html(self, html):
        soup = BeautifulSoup(html, "html.parser")
        found = set()
        for tag in soup.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                found.add(name)
        for a in soup.find_all("a", href=True):
            found.update(re.findall(r"[?&](\w+)=", a["href"]))
        return list(found)

    def get_baseline(self, url):
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            return {
                "status": r.status_code,
                "length": len(r.text),
                "text": r.text,
            }
        except:
            return None

    def is_significantly_different(self, baseline, test):
        if not baseline or not test:
            return False
        if baseline["status"] != test["status"]:
            return True
        delta = abs(len(test["text"]) - baseline["length"])
        return delta > 100

    def check_payload(self, url, payload, baseline):
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
            resp_info = {
                "status": r.status_code,
                "text": r.text,
            }
            if self.is_sqli_error(r.text) and self.is_significantly_different(baseline, resp_info):
                return {"url": url, "payload": payload, "type": "error-based"}

            if self.verbose:
                self.print_status("Not Vuln", url, level="-")
        except Exception as e:
            if self.verbose:
                self.print_error(url, str(e))
        return None

    def print_status(self, status, url, level="*"):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        color = "green" if status.lower() == "vuln" else "red"
        status_colored = self.printer.color_text(status, color)
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
        schemes = ["http", "https"]
        all_params = set()

        for scheme in schemes:
            try:
                url = f"{scheme}://{self.target}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                if r.ok:
                    extracted = self.extract_params_from_html(r.text)
                    all_params.update(extracted)
                    all_params.update(self.COMMON_PARAMS)
                    break
            except:
                continue

        all_params = list(all_params or ["id"])
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for scheme in schemes:
                for param in all_params:
                    base_url = f"{scheme}://{self.target}"
                    baseline_url = f"{base_url}?{urlencode({param: '123'})}"
                    baseline = self.get_baseline(baseline_url)
                    if not baseline:
                        continue
                    for payload in self.payloads:
                        test_url = f"{base_url}?{urlencode({param: payload})}"
                        tasks.append(executor.submit(self.check_payload, test_url, payload, baseline))

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
