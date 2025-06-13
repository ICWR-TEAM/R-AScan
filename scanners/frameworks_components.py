import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class FrameworksComponents:
    def __init__(self, target):
        self.target = target

    def scan(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            headers = r.headers
            return {
                "x-powered-by": headers.get("X-Powered-By", ""),
                "x-generator": headers.get("X-Generator", "")
            }
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return FrameworksComponents(args.target).scan()
