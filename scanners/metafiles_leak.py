import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class MetafilesLeak:
    PATHS = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/config"]

    def __init__(self, target):
        self.target = target

    def scan(self):
        found = {}
        for path in self.PATHS:
            try:
                r = requests.get(f"http://{self.target}{path}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if r.status_code == 200 and r.text.strip():
                    found[path] = r.text.strip()[:200]
            except:
                pass
        return {"metafiles": found}

def scan(args=None):
    return MetafilesLeak(args.target).scan()
