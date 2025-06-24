import requests, os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

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
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self, target):
        exposed = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for path in self.paths:
            try:
                url = f"http://{target}{path}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["password", "user", "host", "env", "config"]):
                    colored_file = self.printer.color_text(path, "yellow")
                    print(f"[*] [Module: {colored_module}] Exposed: {colored_file}")
                    exposed.append({"file": path, "url": url, "status": 200})
            except Exception as e:
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
                exposed.append({"file": path, "error": str(e)})

        if not exposed:
            print(f"[*] [Module: {colored_module}] No sensitive files exposed.")

        return exposed if exposed else [{"exposed_files": False}]

def scan(args=None):
    return SensitiveFileScanner().scan(args.target)
