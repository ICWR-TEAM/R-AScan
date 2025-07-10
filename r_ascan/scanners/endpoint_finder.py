import requests
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class EndpointDump:
    COMMON_ENDPOINT_FILES = [
        "/asset-manifest.json",
        "/ngsw.json",
        "/manifest.json",
        "/routes.json",
    ]

    JS_FILE_EXTENSIONS = [".js", ".mjs"]

    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.found_endpoints = set()
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.thread = args.threads if hasattr(args, "threads") else 5

    def fetch_url(self, url):
        try:
            r = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if r.status_code == 200:
                return r.text
        except:
            return None

    def fetch_urls(self, urls):
        results = {}
        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            futures = {executor.submit(self.fetch_url, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                content = future.result()
                if content:
                    results[url] = content
        return results

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

    def extract_files_dict(self, content):
        import json
        files_dict = {}
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for key in ["files", "routes", "entrypoints", "assets"]:
                    if key in data and isinstance(data[key], dict):
                        files_dict.update(data[key])
        except:
            pass
        return files_dict

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

    def scan_js_files(self, js_files):
        urls = []
        for js_file in js_files:
            urls.append(f"http://{self.target}{js_file}")
            urls.append(f"https://{self.target}{js_file}")
        js_contents = self.fetch_urls(urls)
        for content in js_contents.values():
            self.found_endpoints.update(self.extract_from_html_js(content))

    def run(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")

        urls_to_fetch = []
        for path in self.COMMON_ENDPOINT_FILES + ["/"]:
            urls_to_fetch.append(f"http://{self.target}{path}")
            urls_to_fetch.append(f"https://{self.target}{path}")

        fetched = self.fetch_urls(urls_to_fetch)

        for url, content in fetched.items():
            ep = self.extract_from_json(content)
            if ep:
                self.found_endpoints.update(ep)
            self.found_endpoints.update(self.extract_from_html_js(content))
            files_dict = self.extract_files_dict(content)
            js_files = self.find_js_files(files_dict)
            if js_files:
                self.scan_js_files(js_files)

        if self.found_endpoints:
            print(f"[*] [Module: {colored_module}] [Found {len(self.found_endpoints)} endpoints]")
        else:
            print(f"[*] [Module: {colored_module}] No endpoints found.")

        return {"endpoints_found": list(sorted(self.found_endpoints))}

def scan(args=None):
    return EndpointDump(args).run()
