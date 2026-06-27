import html
import requests, os
import secrets
from urllib.parse import urljoin, urlencode, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS, PARAMS as GLOBAL_PARAMS
from r_ascan.module.other import Other

class Top25FastScanner:
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    PAYLOAD = {
        "SQLi": "'",
        "LFI": "../../../../etc/passwd",
        "OpenRedirect": "https://example.invalid/r-ascan-open-redirect",
        "RCE": ";echo {marker}",
        "SSRF": "http://127.0.0.1/?r_ascan={marker}",
        "XSS": "<r-ascan-xss-{marker}>"
    }

    INDICATORS = {
        "SQLi": [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sqlstate",
            "pg_query",
        ],
        "LFI": ["root:x:0:0", "/bin/bash"],
        "SSRF": ["connection refused", "localhost", "127.0.0.1"],
    }

    PARAMS = GLOBAL_PARAMS

    def __init__(self, args):
        self.target = f"http://{args.target}:{args.port}".rstrip("/") if args.port else f"http://{args.target}".rstrip("/")
        self.verbose = args.verbose
        self.thread = args.threads
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.marker = f"rascan{secrets.token_hex(6)}"

    def scan(self):
        endpoints = open(COMMON_ENDPOINTS, "r").read().splitlines()
        tasks = []
        results = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for category, params in self.PARAMS.items():
                if category not in self.PAYLOAD:
                    continue
                payload = self.PAYLOAD[category].format(marker=self.marker)
                for param in params:
                    for endpoint in endpoints:
                        url = urljoin(self.target, endpoint)
                        baseline = self._baseline(method="GET", url=url, param=param)
                        for method in self.METHODS:
                            tasks.append(executor.submit(
                                self._scan_once, category, method, url, endpoint, param, payload, baseline
                            ))

            for future in as_completed(tasks):
                res = future.result()
                if not res:
                    continue

                is_vuln = res.get("vuln", False)
                status = res.get("status", "-")
                cat = res.get("category", "UNKNOWN")
                method = res.get("method", "-")
                param = res.get("param", "-")

                colored_cat = self.printer.color_text(cat, "yellow")
                colored_target = self.printer.color_text(self.target, "yellow")
                colored_method = self.printer.color_text(method, "magenta")
                colored_param = self.printer.color_text(f"[{param}]", "green")
                colored_status = self.printer.color_text(str(status), "green" if is_vuln else "red")
                message = f"[*] [Module: {colored_module}] [Target: {colored_target}] [Cat: {colored_cat}] [Method: {colored_method}] [Param: {colored_param}] [Status: {colored_status}]"

                if self.verbose or is_vuln:
                    print(message)

                results.append(res)

        return {"target": self.target, "findings": results}

    def _baseline(self, method, url, param):
        try:
            control = f"rascan_control_{self.marker}"
            full_url = f"{url}?{urlencode({param: control})}" if method == "GET" else url
            data = {param: control} if method != "GET" else None
            r = self.session.request(
                method,
                full_url,
                data=data,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            return {"status": r.status_code, "text": r.text, "length": len(r.text)}
        except Exception:
            return None

    def _looks_like_passwd(self, text):
        if "root:x:0:0" not in text or "/bin/" not in text:
            return False
        return sum(1 for line in text.splitlines() if line.count(":") >= 6) >= 3

    def _is_reflected_xss(self, value, text):
        return value in text or html.escape(value, quote=False) in text

    def _is_open_redirect(self, response, expected):
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False
        location = response.headers.get("Location", "")
        parsed = urlparse(location)
        return location.strip() == expected or parsed.netloc.lower() == "example.invalid"

    def _scan_once(self, category, method, url, endpoint, param, value, baseline):
        try:
            data = {param: value}
            full_url = f"{url}?{urlencode(data)}" if method == "GET" else url
            r = self.session.request(method, full_url, data=data if method != "GET" else None, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

            if r.status_code in [401, 403, 404, 405] or r.status_code >= 500:
                return {
                    "category": category,
                    "method": method,
                    "endpoint": endpoint,
                    "param": param,
                    "payload": value,
                    "status": r.status_code,
                    "vuln": False
                }

            text = r.text
            lower_text = text.lower()
            baseline_text = (baseline or {}).get("text", "").lower()
            signs = self.INDICATORS.get(category, [])
            is_vuln = False
            confidence = "none"
            signal = None

            if category == "SQLi":
                signal = next((sig for sig in signs if sig in lower_text and sig not in baseline_text), None)
                is_vuln = signal is not None
                confidence = "medium" if is_vuln else "none"
            elif category == "LFI":
                is_vuln = self._looks_like_passwd(text)
                signal = "passwd-like content" if is_vuln else None
                confidence = "high" if is_vuln else "none"
            elif category == "OpenRedirect":
                is_vuln = self._is_open_redirect(r, value)
                signal = r.headers.get("Location") if is_vuln else None
                confidence = "high" if is_vuln else "none"
            elif category == "RCE":
                is_vuln = self.marker in text and value not in text
                signal = self.marker if is_vuln else None
                confidence = "high" if is_vuln else "none"
            elif category == "SSRF":
                reflected = self.marker in lower_text
                signal = next((sig for sig in signs if sig in lower_text and sig not in baseline_text), None)
                is_vuln = bool(signal and not reflected)
                confidence = "low" if is_vuln else "none"
            elif category == "XSS":
                is_vuln = self._is_reflected_xss(value, text)
                signal = "payload reflected" if is_vuln else None
                confidence = "low" if is_vuln else "none"

            return {
                "category": category,
                "method": method,
                "endpoint": endpoint,
                "param": param,
                "payload": value,
                "status": r.status_code,
                "vuln": is_vuln and confidence != "low",
                "potential": is_vuln and confidence == "low",
                "confidence": confidence,
                "signal": signal,
            }

        except Exception:
            return None

def scan(args=None):
    return Top25FastScanner(args).scan()
