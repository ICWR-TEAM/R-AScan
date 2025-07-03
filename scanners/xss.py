import requests, os, re
from urllib.parse import urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class XSSScanner:
    COMMON_PARAMS = ["q", "search", "id", "page", "lang", "query", "keyword", "file", "ref", "url"]

    def __init__(self, args):
        self.target = args.target
        self.payload = "<script>alert('xss')</script>"
        self.headers = HTTP_HEADERS
        self.timeout = DEFAULT_TIMEOUT
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.verbose = args.verbose

    def run(self):
        base = None
        for proto in ["https://", "http://"]:
            try:
                url = f"{proto}{self.target}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                if resp.status_code < 400:
                    base = url
                    break
            except:
                continue
        if base is None:
            base = f"http://{self.target}"

        result = {
            "reflected": {"vulnerable": False, "url": ""},
            "stored": {"submitted": False, "vulnerable": False, "url": ""},
            "dom": {"vulnerable": False, "scripts": []}
        }

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    executor.submit(self.test_reflected, base): "reflected",
                    executor.submit(self.test_stored, base): "stored",
                }
                for future in as_completed(futures):
                    res = future.result()
                    result.update(res)
            dom_res = self.test_dom(base)
            result.update(dom_res)
        except Exception as e:
            result["error"] = str(e)

        return result

    def extract_parameters_from_html(self, html):
        soup = BeautifulSoup(html, "html.parser")
        params = set()
        for tag in soup.find_all(["input", "textarea"]):
            name = tag.get("name")
            if name:
                params.add(name)
        for a in soup.find_all("a", href=True):
            matches = re.findall(r"[?&](\w+)=", a["href"])
            for match in matches:
                params.add(match)
        return list(params)

    def test_reflected(self, base):
        result = {"reflected": {"vulnerable": False, "url": ""}}
        try:
            r = requests.get(base, headers=self.headers, timeout=self.timeout, verify=False)
            found_params = self.extract_parameters_from_html(r.text)
            total_params = list(set(self.COMMON_PARAMS + found_params)) or ["x"]
            for param in total_params:
                test_url = base + ("&" if "?" in base else "?") + urlencode({param: self.payload})
                resp = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
                is_vuln = self.payload in resp.text
                if is_vuln:
                    result["reflected"]["vulnerable"] = True
                    result["reflected"]["url"] = resp.url
                if self.verbose or is_vuln:
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_url = self.printer.color_text(resp.url, "yellow")
                    status = "Detected" if is_vuln else "Clean"
                    vuln_status = self.printer.color_text("Vuln", "green") if is_vuln else self.printer.color_text("Not Vuln", "red")
                    print(f"[*] [Module: {colored_module}] [{vuln_status}] [Reflected XSS {status}] [Param: {param}] [URL: {colored_url}]")
                if is_vuln:
                    break
        except:
            pass
        return result

    def test_stored(self, base):
        result = {"stored": {"submitted": False, "vulnerable": False, "url": ""}}
        try:
            post_url = base.rstrip("/") + "/post"
            data = {"comment": self.payload}
            post_resp = requests.post(post_url, headers=self.headers, data=data, timeout=self.timeout, verify=False)
            result["stored"]["submitted"] = post_resp.ok
            if post_resp.ok:
                get_resp = requests.get(post_url, headers=self.headers, timeout=self.timeout, verify=False)
                is_vuln = self.payload in get_resp.text
                if is_vuln:
                    result["stored"]["vulnerable"] = True
                    result["stored"]["url"] = post_url
                if self.verbose or is_vuln:
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_url = self.printer.color_text(post_url, "yellow")
                    status = "Detected" if is_vuln else "Clean"
                    print(f"[*] [Module: {colored_module}] [Stored XSS {status}] [URL: {colored_url}]")
        except:
            pass
        return result

    def test_dom(self, base):
        result = {"dom": {"vulnerable": False, "scripts": []}}
        try:
            resp = requests.get(base, headers=self.headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            scripts = soup.find_all("script")
            dom_scripts = []
            for script in scripts:
                content = script.string or ""
                if any(keyword in content for keyword in ["document.location", "document.write", "innerHTML", "eval(", "window.location"]):
                    dom_scripts.append(content.strip()[:100])
            if dom_scripts:
                result["dom"]["vulnerable"] = True
                result["dom"]["scripts"] = dom_scripts
            if self.verbose or dom_scripts:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                print(f"[*] [Module: {colored_module}] [DOM-Based XSS {'Detected' if dom_scripts else 'Clean'}] [Scripts Found: {len(dom_scripts)}]")
        except:
            pass
        return result

def scan(args=None):
    return XSSScanner(args).run()
