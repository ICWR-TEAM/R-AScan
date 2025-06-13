import requests
import re
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class EndpointDump:
    COMMON_ENDPOINT_FILES = [
        "/asset-manifest.json",
        "/ngsw.json",
        "/manifest.json",
        "/routes.json",
    ]

    JS_FILE_EXTENSIONS = [".js", ".mjs"]

    def __init__(self, target):
        self.target = target
        self.found_endpoints = set()
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)

    def fetch_url(self, path):
        url = f"http://{self.target}{path}"
        try:
            r = self.session.get(url, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 200:
                return r.text
        except:
            pass
        return None

    def extract_from_json(self, content):
        import json
        endpoints = set()
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for key in ["files", "routes", "entrypoints", "assets"]:
                    if key in data and isinstance(data[key], dict):
                        endpoints.update(data[key].keys())
                def deep_extract(obj):
                    urls = set()
                    if isinstance(obj, dict):
                        for v in obj.values():
                            urls.update(deep_extract(v))
                    elif isinstance(obj, list):
                        for i in obj:
                            urls.update(deep_extract(i))
                    elif isinstance(obj, str):
                        if obj.startswith("/"):
                            urls.add(obj)
                    return urls
                endpoints.update(deep_extract(data))
        except:
            pass
        return endpoints

    def extract_from_html_js(self, content):
        endpoints = set()
        patterns = [
            r'fetch\([\'"](/[^\'")]+)[\'"]',
            r'axios\([\'"](/[^\'")]+)[\'"]',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/[^"\']+\.(?:php|asp|aspx|jsp))["\']',
            r'["\'](/[^"\']+/[a-zA-Z0-9_\-]+)["\']',
            r'["\'](/[^"\']+)["\']',
        ]
        for pat in patterns:
            matches = re.findall(pat, content)
            endpoints.update(matches)
        return endpoints

    def find_js_files(self, files_dict):
        js_files = set()
        for f in files_dict.keys():
            if any(f.endswith(ext) for ext in self.JS_FILE_EXTENSIONS):
                js_files.add(f)
        return js_files

    def scan_js_files(self, base_path, js_files):
        for js_file in js_files:
            content = self.fetch_url(js_file)
            if content:
                self.found_endpoints.update(self.extract_from_html_js(content))

    def scan(self):
        for path in self.COMMON_ENDPOINT_FILES:
            content = self.fetch_url(path)
            if content:
                ep = self.extract_from_json(content)
                if ep:
                    self.found_endpoints.update(ep)
                self.found_endpoints.update(self.extract_from_html_js(content))
                js_files = self.find_js_files(ep)
                if js_files:
                    self.scan_js_files("/", js_files)

        homepage = self.fetch_url("/")
        if homepage:
            self.found_endpoints.update(self.extract_from_html_js(homepage))

        return {"endpoints_found": list(sorted(self.found_endpoints))}

def scan(args=None):
    scanner = EndpointDump(args.target)
    return scanner.scan()
