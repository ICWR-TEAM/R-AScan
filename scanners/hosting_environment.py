import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class HostingEnvironment:
    def __init__(self, target):
        self.target = target

    def scan(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            text = r.text.lower()
            env = []
            if "cloudflare" in text: env.append("Cloudflare")
            if "amazonaws" in text: env.append("AWS")
            if "azure" in text: env.append("Azure")
            return {"hosting": env}
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return HostingEnvironment(args.target).scan()
