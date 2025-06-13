import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class EntryPoints:
    PATHS = ["/login", "/admin", "/dashboard", "/user", "/account", "/auth"]

    def __init__(self, target):
        self.target = target

    def scan(self):
        found = []
        for path in self.PATHS:
            try:
                r = requests.get(f"http://{self.target}{path}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if r.status_code in [200, 401, 403]:
                    found.append(path)
            except:
                pass
        return {"entry_points": found}

def scan(args=None):
    return EntryPoints(args.target).scan()
