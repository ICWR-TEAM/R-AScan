import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class MetafilesLeak:
    PATHS = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/config"]

    def __init__(self, target):
        self.target = target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        found = {}
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for path in self.PATHS:
            try:
                url = f"http://{self.target}{path}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if r.status_code == 200 and r.text.strip():
                    content_preview = r.text.strip()[:200]
                    colored_path = self.printer.color_text(path, "yellow")
                    print(f"[*] [Module: {colored_module}] [Found: {colored_path}]")
                    found[path] = content_preview
            except Exception as e:
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")

        if not found:
            print(f"[*] [Module: {colored_module}] No metafiles found.")

        return {"metafiles": found}

def scan(args=None):
    return MetafilesLeak(args.target).scan()
