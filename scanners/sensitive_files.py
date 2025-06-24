import requests, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HTTP_HEADERS, DEFAULT_TIMEOUT, SENSITIVE_FILES
from module.other import Other

class SensitiveFileScanner:
    def __init__(self, args):
        self.target = args.target
        self.verbose = args.verbose
        self.thread = args.threads
        self.paths = open(SENSITIVE_FILES, "r").read().splitlines()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def check_file(self, path):
        url = f"http://{self.target}{path}"
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            keywords = ["password", "user", "host", "env", "config"]
            if self.verbose or (response.status_code == 200 and any(k in response.text.lower() for k in keywords)):
                return {
                    "file": path,
                    "url": url,
                    "status": response.status_code,
                    "content": response.text if self.verbose else None
                }
        except Exception as e:
            return {"file": path, "error": str(e)}
        return None

    def scan(self):
        exposed = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            futures = {executor.submit(self.check_file, path): path for path in self.paths}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    exposed.append(result)
                    colored_file = self.printer.color_text(result["file"], "yellow")
                    if "status" in result:
                        colored_status_code = self.printer.color_text(result["status"], "green" if result["status"] == 200 else "red")
                        print(f"[*] [Module: {colored_module}] [File: {colored_file}] [Status Code: {colored_status_code}]")
                    elif "error" in result:
                        colored_error = self.printer.color_text(result["error"], "red")
                        print(f"[!] [Module: {colored_module}] [File: {colored_file}] [Error: {colored_error}]")

        if not exposed:
            print(f"[*] [Module: {colored_module}] No sensitive files exposed.")

        return exposed if exposed else [{"exposed_files": False}]

def scan(args=None):
    return SensitiveFileScanner(args).scan()
