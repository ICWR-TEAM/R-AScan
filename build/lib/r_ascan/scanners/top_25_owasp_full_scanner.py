import requests, os
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS, PARAMS as GLOBAL_PARAMS
from r_ascan.module.other import Other

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
        "SQLi": ["mysql", "syntax", "sql", "query failed"],
        "LFI": ["root:x:0:0", "/bin/bash"],
        "OpenRedirect": ["evil.com"],
        "RCE": ["uid=", "gid="],
        "SSRF": ["localhost", "127.0.0.1"],
        "XSS": ["<script>alert(1)</script>"]
    }

    PARAMS = GLOBAL_PARAMS

    def __init__(self, args):
        self.target = f"http://{args.target}:{args.port}".rstrip("/") if args.port else f"http://{args.target}".rstrip("/")
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
                if not res:
                    continue

                is_vuln = res.get("vuln", False)
                status = res.get("status", "-")
                cat = res.get("category", "UNKNOWN")
                method = res.get("method", "-")
                param = res.get("param", "-")

                colored_cat = self.printer.color_text(cat, "yellow")
                colored_target = self.printer.color_text(self.target, "yellow")
                colored_method = self.printer.color_text(method, "magenta")
                colored_param = self.printer.color_text(f"[{param}]", "green")
                colored_status = self.printer.color_text(str(status), "green" if is_vuln else "red")
                message = f"[*] [Module: {colored_module}] [Target: {colored_target}] [Cat: {colored_cat}] [Method: {colored_method}] [Param: {colored_param}] [Status: {colored_status}]"

                if self.verbose or is_vuln:
                    print(message)

                results.append(res)

        return {"target": self.target, "findings": results}

    def _scan_once(self, category, method, url, endpoint, param, value):
        try:
            data = {param: value}
            full_url = f"{url}?{urlencode(data)}" if method == "GET" else url
            r = self.session.request(method, full_url, data=data if method != "GET" else None, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

            if r.status_code in [401, 403, 404, 405] or r.status_code >= 500:
                return {
                    "category": category,
                    "method": method,
                    "endpoint": endpoint,
                    "param": param,
                    "payload": value,
                    "status": r.status_code,
                    "vuln": False
                }

            signs = self.INDICATORS.get(category, [])
            is_vuln = any(sig.lower() in r.text.lower() for sig in signs)

            return {
                "category": category,
                "method": method,
                "endpoint": endpoint,
                "param": param,
                "payload": value,
                "status": r.status_code,
                "vuln": is_vuln
            }

        except Exception:
            return None

def scan(args=None):
    return Top25FastScanner(args).scan()
