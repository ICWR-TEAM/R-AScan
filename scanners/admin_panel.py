import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class AdminPanelScanner:
    def __init__(self):
        self.paths = ["/admin", "/admin/login", "/administrator", "/adminpanel", "/cpanel"]

    def scan(self, target):
        found = []
        for path in self.paths:
            try:
                url = f"http://{target}{path}"
                response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                if response.status_code in [200, 401, 403]:
                    found.append({"path": path, "status": response.status_code})
            except Exception as e:
                found.append({"error": str(e), "path": path})
        return found if found else [{"admin_panel_found": False}]

def scan(args=None):
    return AdminPanelScanner().scan(args.target)
