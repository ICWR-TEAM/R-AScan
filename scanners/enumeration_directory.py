import requests
import os
from config import HTTP_HEADERS, DEFAULT_TIMEOUT
from concurrent.futures import ThreadPoolExecutor, as_completed
from module.other import Other

class EnumerationDirectoryScanner:
    def __init__(self, args):
        self.target = args.target
        self.max_workers = args.threads
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.paths = [
            "/admin", "/admin/", "/admin/login", "/admin_login", "/admin-area",
            "/administrator", "/administrator/", "/administrator/login",
            "/adminpanel", "/adminpanel/", "/admincp", "/adminControlPanel",
            "/cpanel", "/cpanel/", "/login", "/login/admin", "/admin/login.php",
            "/admin/index.php", "/admin1", "/admin2", "/admin3",
            "/admin/home", "/admin_console", "/admin_area", "/adminAccount",
            "/controlpanel", "/controlpanel/login", "/manage", "/manage/login",
            "/panel", "/panel/", "/dashboard", "/dashboard/login",
            "/cms", "/cms/login", "/moderator", "/moderator/login",
            "/useradmin", "/users/admin", "/backend", "/backend/login",
            "/system", "/system/admin", "/adminsite", "/secureadmin",
            "/wp-admin", "/wp-login.php",
            "/joomla/administrator",
            "/drupal/admin",
            "/typo3/backend",
            "/bitrix/admin",
            "/webadmin", "/webadmin/login",
            "/admin.php", "/admin.html", "/administrator.php"
        ]

    def check_path(self, protocol, path):
        url = f"{protocol}://{self.target}{path}"
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            if response.status_code in [200, 401, 403]:
                return {"url": url, "status": response.status_code}
        except Exception as e:
            return {"url": url, "error": str(e)}
        return None

    def run(self):
        found = []
        tasks = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for path in self.paths:
                for protocol in ["http", "https"]:
                    tasks.append(executor.submit(self.check_path, protocol, path))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    found.append(result)
                    colored_module = self.printer.color_text(self.module_name, "cyan")
                    colored_url = self.printer.color_text(result.get("url", ""), "yellow")
                    if "status" in result:
                        status_color = "green" if result["status"] == 200 else "red"
                        colored_status = self.printer.color_text(str(result["status"]), status_color)
                        print(f"[*] [Module: {colored_module}] [URL: {colored_url}] [Status: {colored_status}]")
                    elif "error" in result:
                        colored_error = self.printer.color_text(result["error"], "red")
                        print(f"[!] [Module: {colored_module}] [URL: {colored_url}] [Error: {colored_error}]")

        return found if found else [{"admin_panel_found": False}]

def scan(args=None):
    return EnumerationDirectoryScanner(args).run()
