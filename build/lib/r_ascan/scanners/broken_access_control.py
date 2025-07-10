import requests, re, json, os, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS
from r_ascan.module.other import Other

class BrokenAccessControlScanner:
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    def __init__(self, args):
        self.verbose = args.verbose
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.session.timeout = DEFAULT_TIMEOUT
        self.found_endpoints = set()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.thread = args.threads
        self.baseline = self._get_baseline_response()

    def _get_baseline_response(self):
        baseline = {}
        random_number = random.randint(100000, 999999)
        fake_path = f"/___random_path_{random_number}__"
        for proto in ["http", "https"]:
            try:
                url = f"{proto}://{self.target}{fake_path}"
                r = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False, verify=False)
                status_code = r.status_code
                content_length = len(r.content)
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_proto = self.printer.color_text(proto.upper(), "magenta")
                colored_code = self.printer.color_text(str(status_code), "yellow")
                colored_len = self.printer.color_text(str(content_length), "yellow")
                print(f"[*] [Module: {colored_module}] [Baseline: {colored_proto} {fake_path}] [Status: {colored_code}] [Length: {colored_len}]")
                baseline[proto] = {
                    "status_code": status_code,
                    "content_length": content_length
                }
            except:
                continue
        return baseline

    def _is_similar_to_baseline(self, proto, status_code, content_length):
        base = self.baseline.get(proto, {"status_code": 404, "content_length": 0})
        if status_code != base["status_code"]:
            return False
        return abs(content_length - base["content_length"]) < 20

    def run(self):
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
                        tasks.append(executor.submit(self._request, method, url, protocol))
            for future in as_completed(tasks):
                result = future.result()
                if not result:
                    continue
                method, url, status, proto, length = result
                path = url[len(f"http://{self.target}"):] if url.startswith(f"http://{self.target}") else url[len(f"https://{self.target}"):]                
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_method = self.printer.color_text(method, "magenta")
                colored_path = self.printer.color_text(path, "yellow")
                colored_status = self.printer.color_text(
                    str(status), "green" if status in [200, 201, 202, 203, 204, 206, 207] else "red"
                )
                is_similar = self._is_similar_to_baseline(proto, status, length)
                if self.verbose or (status in [200, 201, 202, 203, 204, 206, 207] and not is_similar):
                    print(f"[*] [Module: {colored_module}] [Method: {colored_method}] [Path: {colored_path}] [Status: {colored_status}]")
                if status in [200, 201, 202, 203, 204, 206, 207] and not is_similar:
                    bac_results.append({
                        "method": method,
                        "path": path,
                        "status": status
                    })
        return {
            "target": self.target,
            "potential_bac": bac_results,
            "tested": len(self.found_endpoints) * len(self.METHODS) * len(protocols),
            "baseline": self.baseline
        }

    def _request(self, method, url, proto):
        try:
            res = self.session.request(method, url, json={}, timeout=DEFAULT_TIMEOUT, allow_redirects=False, verify=False)
            return (method, url, res.status_code, proto, len(res.content))
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
        if len(self.found_endpoints) == 0:
            try:
                with open(COMMON_ENDPOINTS, "r") as f:
                    self.found_endpoints.update([line.strip() for line in f if line.strip()])
            except:
                pass

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
    return BrokenAccessControlScanner(args).run()
