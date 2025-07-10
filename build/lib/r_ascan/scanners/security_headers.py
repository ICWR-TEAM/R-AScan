import requests, os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class SecurityHeaderScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        try:
            response = self._get_response(self.target)
            return self._check_headers(response)
        except Exception as e:
            if self.verbose:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
            return {"error": str(e)}

    def _get_response(self, target):
        for scheme in ["https://", "http://"]:
            try:
                url = f"{scheme}{target}"
                res = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                res.raise_for_status()
                return res
            except requests.RequestException:
                continue
        raise Exception("Cannot access target.")

    def _check_headers(self, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        found = {h: headers[h.lower()] for h in self.required_headers if h.lower() in headers}
        missing = [h for h in self.required_headers if h.lower() not in headers]

        colored_module = self.printer.color_text(self.module_name, "cyan")
        for h in found:
            colored_h = self.printer.color_text(h, "green")
            print(f"[*] [Module: {colored_module}] [Found Header: {colored_h}]")
        for h in missing:
            colored_h = self.printer.color_text(h, "red")
            print(f"[*] [Module: {colored_module}] [Missing Header: {colored_h}]")

        return {
            "found": found,
            "missing": missing,
            "score": f"{len(found)}/{len(self.required_headers)}"
        }

def scan(args=None):
    return SecurityHeaderScanner(args).scan()
