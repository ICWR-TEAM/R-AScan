import requests, time, os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class RateLimitingScanner:
    def __init__(self, args, test_path="/", max_requests=20, interval=1):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.test_path = test_path
        self.max_requests = max_requests
        self.interval = interval
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        url = f"http://{self.target}{self.test_path}"
        statuses = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for _ in range(self.max_requests):
            try:
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                statuses.append(r.status_code)
                time.sleep(self.interval / self.max_requests)
            except Exception as e:
                if self.verbose:
                    colored_error = self.printer.color_text(str(e), "red")
                    print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
                return {"error": str(e)}

        rate_limited = any(s in [429, 503] for s in statuses)
        if rate_limited:
            codes = [s for s in statuses if s in [429, 503]]
            colored_status = self.printer.color_text("Rate Limiting Detected", "yellow")
            print(f"[*] [Module: {colored_module}] {colored_status} Codes: {codes}")
        else:
            print(f"[*] [Module: {colored_module}] No rate limiting behavior detected.")

        return {
            "requests_made": self.max_requests,
            "status_codes": statuses,
            "rate_limited": rate_limited,
            "rate_limit_status_codes": [s for s in statuses if s in [429, 503]],
        }

def scan(args=None):
    scanner = RateLimitingScanner(args)
    return scanner.scan()
