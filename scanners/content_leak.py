import requests
import re
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class ContentLeak:
    def __init__(self, target):
        self.target = target

    def scan(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            comments = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
            return {"comments": comments[:5]}
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return ContentLeak(args.target).scan()
