import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class SensitiveFileScanner:
    def __init__(self):
        self.paths = [
            "/.env",
            "/.git/config",
            "/.gitignore",
            "/.htaccess",
            "/sftp-config.json",
            "/ftpconfig",
            "/config.json",
            "/config.yml",
            "/web.config",
            "/composer.lock",
            "/package-lock.json",
            "/.DS_Store"
        ]

    def scan(self, target):
        exposed = []
        for path in self.paths:
            try:
                url = f"http://{target}{path}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["password", "user", "host", "env", "config"]):
                    exposed.append({"file": path, "url": url, "status": 200})
            except Exception as e:
                exposed.append({"file": path, "error": str(e)})
        return exposed if exposed else [{"exposed_files": False}]

def scan(args=None):
    return SensitiveFileScanner().scan(args.target)
