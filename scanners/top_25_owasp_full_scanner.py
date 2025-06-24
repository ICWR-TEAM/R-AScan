import requests, os
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS, PARAMS as GLOBAL_PARAMS
from module.other import Other

class Top25FastScanner:
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    PAYLOAD = {
        "SQLi": "1 OR 1=1",
        "LFI": "../../../../etc/passwd",
        "OpenRedirect": "http://evil.com",
        "RCE": "id",
        "SSRF": "http://127.0.0.1",
        "XSS": "<script>alert(1)</script>"
    }

    INDICATORS = {
        "SQLi": ["mysql", "syntax", "sql error", "query failed"],
        "LFI": ["root:x:0:0", "/bin/bash"],
        "OpenRedirect": ["evil.com"],
        "RCE": ["uid=", "gid=", "root"],
        "SSRF": ["localhost", "127.0.0.1"],
        "XSS": ["<script>alert(1)</script>", "alert(1)"]
    }

    PARAMS = GLOBAL_PARAMS

    def __init__(self, args):
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
                            tasks.append(
                                executor.submit(
                                    self._scan_once, category, method, url, endpoint, param, payload
                                )
                            )

            for future in as_completed(tasks):
                res = future.result()
                if res or self.verbose:
                    cat = res["category"] if res else "UNKNOWN"
                    method = res["method"] if res else "-"
                    param = res["param"] if res else "-"
                    status = res["status"] if res else "Not Vuln"

                    colored_cat = self.printer.color_text(cat, "yellow")
                    colored_method = self.printer.color_text(method, "magenta")
                    colored_param = self.printer.color_text(f"[{param}]", "green")
                    colored_status = self.printer.color_text(str(status), "green" if status == 200 else "red")

                    print(f"[*] [Module: {colored_module}] [Cat: {colored_cat}] [Method: {colored_method}] [Param: {colored_param}] [Status: {colored_status}]")

                if res:
                    results.append(res)

        return {"target": self.target, "findings": results}

    def _scan_once(self, category, method, url, endpoint, param, value):
        try:
            data = {param: value}
            if method == "GET":
                r = self.session.get(f"{url}?{urlencode(data)}", timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            else:
                r = self.session.request(method, url, data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

            if r.status_code not in [401, 403, 404, 405] and r.status_code < 500:
                indicators = self.INDICATORS.get(category, [])
                if any(i in r.text.lower() for i in indicators):
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
