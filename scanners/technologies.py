import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class Technologies:
    def __init__(self, target):
        self.target = target

    def scan(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            text = r.text.lower()
            techs = []
            if "php" in text: techs.append("PHP")
            if "wordpress" in text: techs.append("WordPress")
            if "react" in text: techs.append("React")
            if "django" in text: techs.append("Django")
            return {"technologies": techs}
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return Technologies(args.target).scan()
