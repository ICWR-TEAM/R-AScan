import requests, os
from urllib.parse import urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class XSSScanner:
    def __init__(self, args):
        self.target = args.target
        self.payload = "<script>alert('xss')</script>"
        self.headers = HTTP_HEADERS
        self.timeout = DEFAULT_TIMEOUT
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

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

    def test_reflected(self, base):
        result = {"reflected": {"vulnerable": False, "url": ""}}
        try:
            test_url = base + ("&" if "?" in base else "?") + urlencode({"q": self.payload})
            resp = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            if self.payload in resp.text:
                result["reflected"]["vulnerable"] = True
                result["reflected"]["url"] = resp.url
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(resp.url, "yellow")
                print(f"[*] [Module: {colored_module}] [Reflected XSS Detected] [URL: {colored_url}]")
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
                if self.payload in get_resp.text:
                    result["stored"]["vulnerable"] = True
                    result["stored"]["url"] = post_url
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_url = self.printer.color_text(post_url, "yellow")
                    print(f"[*] [Module: {colored_module}] [Stored XSS Detected] [URL: {colored_url}]")
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
                colored_module = self.printer.color_text(self.module_name, "cyan")
                print(f"[*] [Module: {colored_module}] [DOM-Based XSS Detected] [Scripts Found: {len(dom_scripts)}]")
        except:
            pass
        return result

def scan(args=None):
    return XSSScanner(args).run()
