import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class EntryPoints:
    PATHS = ["/login", "/admin", "/dashboard", "/user", "/account", "/auth"]

    def __init__(self, target):
        self.target = target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        found = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for path in self.PATHS:
            try:
                url = f"http://{self.target}{path}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if r.status_code in [200, 401, 403]:
                    colored_path = self.printer.color_text(path, "yellow")
                    colored_status = self.printer.color_text(str(r.status_code), "green" if r.status_code == 200 else "red")
                    print(f"[*] [Module: {colored_module}] [Path: {colored_path}] [Status: {colored_status}]")
                    found.append(path)
            except Exception as e:
                continue

        if not found:
            print(f"[*] [Module: {colored_module}] No entry points found.")

        return {"entry_points": found}

def scan(args=None):
    return EntryPoints(args.target).scan()
