import requests, os, random
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT, COMMON_ENDPOINTS
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.module.other import Other

class AccessControlScanner:
    SENSITIVE_ENDPOINTS = [
        "/admin", "/admin/dashboard", "/admin/login",
        "/user/profile", "/user/settings",
        "/api/admin", "/api/private", "/api/user",
        "/config", "/.env", "/backup.zip",
    ]

    def __init__(self, args):
        self.args = args
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.max_workers = args.threads
        self.printer = Other()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.SENSITIVE_ENDPOINTS += [line.strip() for line in open(COMMON_ENDPOINTS) if line.strip()]
        self.baseline = self.get_baseline_response()

    def get_baseline_response(self):
        random_number = random.randint(100000, 999999)
        fake_path = f"/__random_path_{random_number}__"
        baseline = {}
        for proto in ["http", "https"]:
            try:
                url = f"{proto}://{self.target}{fake_path}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                status_code = r.status_code
                content_length = len(r.content)
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_proto = self.printer.color_text(proto.upper(), "magenta")
                colored_code = self.printer.color_text(str(status_code), "yellow")
                colored_len = self.printer.color_text(str(content_length), "yellow")
                print(f"[*] [Module: {colored_module}] [Baseline: {colored_proto} {fake_path}] [Status: {colored_code}] [Length: {colored_len}]")
                baseline[proto] = {
                    "status_code": status_code,
                    "content_length": content_length
                }
            except:
                continue
        if not baseline:
            baseline["http"] = {"status_code": 404, "content_length": 0}
            baseline["https"] = {"status_code": 404, "content_length": 0}
        return baseline

    def is_similar_to_baseline(self, proto, status_code, content_length):
        base = self.baseline.get(proto, {"status_code": 404, "content_length": 0})
        if status_code != base["status_code"]:
            return False
        return abs(content_length - base["content_length"]) < 20

    def check_endpoint(self, protocol, endpoint):
        url = f"{protocol}://{self.target}{endpoint}"
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            status_code = r.status_code
            content_length = len(r.content)
            redirect = r.headers.get("Location", None)
            is_similar = self.is_similar_to_baseline(protocol, status_code, content_length)
            is_vuln = status_code in [200, 201, 202, 204] and not is_similar
            if self.verbose or is_vuln:
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_url = self.printer.color_text(url, "yellow")
                colored_status = self.printer.color_text(str(status_code), "green" if is_vuln else "red")
                colored_redirect = self.printer.color_text(str(redirect), "magenta")
                print(f"[+] [Module: {colored_module}] [URL: {colored_url}] [Status Code: {colored_status}] [Redirect: {colored_redirect}]")
            return {
                "url": url,
                "status_code": status_code,
                "content_length": content_length,
                "redirect_location": redirect,
                "baseline_like": is_similar,
                "vulnerable": is_vuln
            }
        except Exception as e:
            if self.verbose:
                print(f"[-] [Module: {self.module_name}] [Error: {e}]")
            return {"url": url, "error": str(e)}

    def scan(self):
        results = []
        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for endpoint in self.SENSITIVE_ENDPOINTS:
                for protocol in ["http", "https"]:
                    tasks.append(executor.submit(self.check_endpoint, protocol, endpoint))
            for future in as_completed(tasks):
                results.append(future.result())
        return {
            "access_control_results": results,
            "baseline": self.baseline
        }

def scan(args=None):
    return AccessControlScanner(args).scan()
