import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class BackupFileScanner:
    def __init__(self):
        self.paths = ['.env', 'index.php~', 'index.php.bak', 'backup.zip', 'db.sql']

    def scan(self, target):
        for path in self.paths:
            try:
                url = f"http://{target}/{path}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if r.status_code == 200 and len(r.content) > 50:
                    return {"vulnerability": "Backup File Accessible", "file": path, "status": "vulnerable"}
            except:
                continue
        return {"vulnerability": "Backup File Accessible", "status": "not detected"}

def scan(args=None):
    return BackupFileScanner().scan(args.target)
