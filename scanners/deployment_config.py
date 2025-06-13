import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class DeploymentConfig:
    def __init__(self, target):
        self.target = target

    def scan(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            text = r.text.lower()
            configs = []
            if "debug" in text: configs.append("Debug")
            if "staging" in text: configs.append("Staging")
            if "production" in text: configs.append("Production")
            return {"deployment": configs}
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return DeploymentConfig(args.target).scan()
