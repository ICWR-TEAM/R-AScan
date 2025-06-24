import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from module.other import Other

class BackupFileScanner:
    def __init__(self):
        self.paths = ['.env', 'index.php~', 'index.php.bak', 'backup.zip', 'db.sql']
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self, target):
        for path in self.paths:
            try:
                url = f"http://{target}/{path}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if r.status_code == 200 and len(r.content) > 50:
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_path = self.printer.color_text(path, "yellow")
                    colored_status = self.printer.color_text(str(r.status_code), "green")
                    print(f"[*] [Module: {colored_module}] [File: {colored_path}] [Status: {colored_status}]")
                    return {"vulnerability": "Backup File Accessible", "file": path, "status": "vulnerable"}
            except Exception as e:
                continue

        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] No backup file found.")
        return {"vulnerability": "Backup File Accessible", "status": "not detected"}

def scan(args=None):
    return BackupFileScanner().scan(args.target)
