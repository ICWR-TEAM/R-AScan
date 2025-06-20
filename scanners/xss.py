import requests
from urllib.parse import urlencode
from bs4 import BeautifulSoup
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class XSSScanner:
    def __init__(self):
        self.payload = "<script>alert('xss')</script>"
        self.headers = HTTP_HEADERS
        self.timeout = DEFAULT_TIMEOUT

    def scan(self, target):
        base = target if target.startswith("http") else f"http://{target}"
        result = {
            "reflected": {"vulnerable": False, "url": ""},
            "stored": {"submitted": False, "vulnerable": False, "url": ""},
            "dom": {"vulnerable": False, "scripts": []}
        }
        try:
            result.update(self.test_reflected(base))
            result.update(self.test_stored(base))
            result.update(self.test_dom(base))
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
        except:
            pass
        return result

def scan(args=None):
    return XSSScanner().scan(args.target)
