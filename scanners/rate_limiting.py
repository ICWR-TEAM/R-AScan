import requests
import time
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class RateLimitingScanner:
    def __init__(self, target, test_path="/", max_requests=20, interval=1):
        self.target = target
        self.test_path = test_path
        self.max_requests = max_requests
        self.interval = interval

    def scan(self):
        url = f"http://{self.target}{self.test_path}"
        statuses = []
        for _ in range(self.max_requests):
            try:
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                statuses.append(r.status_code)
                time.sleep(self.interval / self.max_requests)
            except Exception as e:
                return {"error": str(e)}

        rate_limited = any(s in [429, 503] for s in statuses)
        return {
            "requests_made": self.max_requests,
            "status_codes": statuses,
            "rate_limited": rate_limited,
            "rate_limit_status_codes": [s for s in statuses if s in [429, 503]],
        }

def scan(args=None):
    scanner = RateLimitingScanner(args.target)
    return scanner.scan()
