import requests, re, json, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class BrokenAccessControlScanner:
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    def __init__(self, args):
        self.verbose = args.verbose
        self.target = args.target
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.session.timeout = DEFAULT_TIMEOUT
        self.found_endpoints = set()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.thread = args.threads

    def scan(self):
        self._collect_endpoints()
        bac_results = []
        tasks = []

        protocols = ["http", "https"]

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for path in self.found_endpoints:
                for protocol in protocols:
                    base_url = f"{protocol}://{self.target}"
                    for method in self.METHODS:
                        url = f"{base_url}{path}"
                        tasks.append(executor.submit(self._request, method, url))

            for future in as_completed(tasks):
                result = future.result()
                if not result:
                    continue
                method, url, status = result
                path = url[len(f"http://{self.target}"):] if url.startswith(f"http://{self.target}") else url[len(f"https://{self.target}"):]

                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_method = self.printer.color_text(method, "magenta")
                colored_path = self.printer.color_text(path, "yellow")
                colored_status = self.printer.color_text(
                    str(status), "green" if status in [200, 201, 202, 203, 204, 206, 207] else "red"
                )

                if self.verbose or status in [200, 201, 202, 203, 204, 206, 207]:
                    print(f"[*] [Module: {colored_module}] [Method: {colored_method}] [Path: {colored_path}] [Status: {colored_status}]")

                if status in [200, 201, 202, 203, 204, 206, 207]:
                    bac_results.append({
                        "method": method,
                        "path": path,
                        "status": status
                    })

        return {
            "target": self.target,
            "potential_bac": bac_results,
            "tested": len(self.found_endpoints) * len(self.METHODS) * len(protocols)
        }

    def _request(self, method, url):
        try:
            res = self.session.request(method, url, json={}, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            return (method, url, res.status_code)
        except:
            return None

    def _collect_endpoints(self):
        common_files = [
            "/asset-manifest.json",
            "/ngsw.json",
            "/manifest.json",
            "/routes.json",
        ]

        for path in common_files + ["/"]:
            content_http = self._fetch_url(f"http://{self.target}{path}")
            content_https = self._fetch_url(f"https://{self.target}{path}")

            for content in [content_http, content_https]:
                if content:
                    self.found_endpoints.update(self._extract_from_html_js(content))
                    self.found_endpoints.update(self._extract_from_json(content))
                    js_files = self._find_js_files(content)
                    for js in js_files:
                        js_content_http = self._fetch_url(f"http://{self.target}{js}")
                        js_content_https = self._fetch_url(f"https://{self.target}{js}")
                        for js_content in [js_content_http, js_content_https]:
                            if js_content:
                                self.found_endpoints.update(self._extract_from_html_js(js_content))

    def _fetch_url(self, url):
        try:
            res = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
            if res.status_code == 200:
                return res.text
        except:
            return None

    def _extract_from_json(self, content):
        endpoints = set()
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for key in ["files", "routes", "entrypoints", "assets"]:
                    if key in data and isinstance(data[key], dict):
                        endpoints.update(data[key].keys())

                def deep(obj):
                    urls = set()
                    if isinstance(obj, dict):
                        for v in obj.values():
                            urls.update(deep(v))
                    elif isinstance(obj, list):
                        for i in obj:
                            urls.update(deep(i))
                    elif isinstance(obj, str) and obj.startswith("/"):
                        urls.add(obj)
                    return urls

                endpoints.update(deep(data))
        except:
            pass
        return endpoints

    def _extract_from_html_js(self, content):
        patterns = [
            r'fetch\(["\'](/[^"\')]+)["\']',
            r'axios\(["\'](/[^"\')]+)["\']',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/[^"\']+\.(php|asp|aspx|jsp))["\']',
            r'["\'](/[^"\']+/[a-zA-Z0-9_\-]+)["\']',
            r'["\'](/[^"\']+)["\']',
        ]
        endpoints = set()
        for pat in patterns:
            endpoints.update(re.findall(pat, content))

        return {e if isinstance(e, str) else e[0] for e in endpoints}

    def _find_js_files(self, content):
        js_files = set()
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for value in data.values():
                    if isinstance(value, str) and value.endswith((".js", ".mjs")):
                        js_files.add(value)
        except:
            pass
        return js_files

def scan(args=None):
    return BrokenAccessControlScanner(args).scan()
