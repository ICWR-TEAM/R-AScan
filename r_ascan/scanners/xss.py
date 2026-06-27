import html
import requests, os, re, secrets
from urllib.parse import urlencode, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class XSSScanner:
    COMMON_PARAMS = ["q", "search", "id", "page", "lang", "query", "keyword", "file", "ref", "url"]

    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.marker = f"rascan_xss_{secrets.token_hex(6)}"
        self.payload = f'"><svg data-rascan="{self.marker}" onload=alert(1)>'
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
                evidence = self._classify_reflection(resp.text)
                is_vuln = evidence["status"] == "confirmed"
                if self.verbose or is_vuln:
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_url = self.printer.color_text(resp.url, "yellow")
                    vuln_status = self.printer.color_text("Vuln", "green") if is_vuln else self.printer.color_text("Not Vuln", "red")
                    print(f"[*] [Module: {colored_module}] [{vuln_status}] [Reflected XSS] [Param: {param}] [URL: {colored_url}]")
                if is_vuln:
                    result["reflected"]["vulnerable"] = True
                    result["reflected"]["url"] = resp.url
                    result["reflected"]["confidence"] = "medium"
                    result["reflected"]["evidence"] = evidence
                    break
                if evidence["status"] == "potential" and not result["reflected"].get("potential"):
                    result["reflected"].update({
                        "potential": True,
                        "url": resp.url,
                        "confidence": "low",
                        "evidence": evidence,
                    })

            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                method = form.get("method", "get").lower()
                raw_action = form.get("action")
                if raw_action is None or raw_action.strip() == "":
                    action_url = base
                else:
                    action_url = urljoin(base, raw_action)

                inputs = form.find_all("input")
                params = {}
                for i in inputs:
                    name = i.get("name")
                    if name:
                        params[name] = self.payload

                if method == "get":
                    resp = requests.get(action_url, headers=self.headers, params=params, timeout=self.timeout, verify=False)
                else:
                    resp = requests.post(action_url, headers=self.headers, data=params, timeout=self.timeout, verify=False)

                evidence = self._classify_reflection(resp.text)
                is_vuln = evidence["status"] == "confirmed"
                if self.verbose or is_vuln:
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_url = self.printer.color_text(resp.url, "yellow")
                    colored_method = self.printer.color_text(method, "yellow")
                    vuln_status = self.printer.color_text("Vuln", "green") if is_vuln else self.printer.color_text("Not Vuln", "red")
                    print(f"[*] [Module: {colored_module}] [{vuln_status}] [Reflected XSS] [Method: {colored_method}] [Form Action: {action_url}] [URL: {colored_url}]")
                if is_vuln:
                    result["reflected"]["vulnerable"] = True
                    result["reflected"]["url"] = resp.url
                    result["reflected"]["confidence"] = "medium"
                    result["reflected"]["evidence"] = evidence
                    break
                if evidence["status"] == "potential" and not result["reflected"].get("potential"):
                    result["reflected"].update({
                        "potential": True,
                        "url": resp.url,
                        "confidence": "low",
                        "evidence": evidence,
                    })
        except:
            pass
        return result

    def _classify_reflection(self, text):
        raw_marker = self.marker in text
        escaped_marker = html.escape(self.marker) in text
        escaped_payload = html.escape(self.payload, quote=True) in text
        executable_pattern = re.compile(
            rf"<svg\b[^>]*data-rascan=[\"']?{re.escape(self.marker)}[\"']?[^>]*\bonload\s*=",
            re.IGNORECASE,
        )
        if executable_pattern.search(text):
            return {"status": "confirmed", "reason": "payload reflected in executable svg onload context"}
        if raw_marker or escaped_marker or escaped_payload:
            return {"status": "potential", "reason": "payload marker reflected without confirmed executable context"}
        return {"status": "none", "reason": "payload marker not reflected"}

    def test_dom(self, base):
        result = {"dom": {"vulnerable": False, "scripts": []}}
        try:
            resp = requests.get(base, headers=self.headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            scripts = soup.find_all("script")
            dom_scripts = []
            for script in scripts:
                content = script.string or ""
                if self._has_dom_xss_sink(content):
                    dom_scripts.append(content.strip()[:100])
            if dom_scripts:
                result["dom"]["vulnerable"] = False
                result["dom"]["potential"] = True
                result["dom"]["scripts"] = dom_scripts
            if self.verbose or dom_scripts:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                print(f"[*] [Module: {colored_module}] [DOM-Based XSS {'Detected' if dom_scripts else 'Clean'}] [Scripts Found: {len(dom_scripts)}]")
        except:
            pass
        return result

    def _has_dom_xss_sink(self, content):
        source = any(k in content for k in ["location.search", "location.hash", "document.URL", "document.location", "window.location"])
        sink = any(k in content for k in ["document.write", "innerHTML", "outerHTML", "insertAdjacentHTML", "eval("])
        sanitizer = any(k in content for k in ["textContent", "innerText", "encodeURIComponent", "DOMPurify", "sanitize"])
        return source and sink and not sanitizer

def scan(args=None):
    return XSSScanner(args).run()
