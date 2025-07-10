import requests, os, random
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT, DIRECTORIES
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.module.other import Other

class EnumerationDirectoryScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.max_workers = args.threads
        self.verbose = args.verbose
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.paths = open(DIRECTORIES, "r").read().splitlines()
        self.baseline_bodies = {}

    def get_baseline(self, protocol):
        rand_path = f"/__nonexistent_{random.randint(100000,999999)}"
        url = f"{protocol}://{self.target}{rand_path}"
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            return response.text.strip()
        except Exception:
            return ""

    def is_similar_to_baseline(self, protocol, content):
        baseline = self.baseline_bodies.get(protocol)
        if not baseline or not content:
            return False
        content = content.strip()
        if abs(len(content) - len(baseline)) < 30:
            return baseline[:50].lower() == content[:50].lower()
        return False

    def check_path(self, protocol, path):
        url = f"{protocol}://{self.target}{path}"
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            status = response.status_code
            if status in [200, 401, 403]:
                if status == 200 and self.is_similar_to_baseline(protocol, response.text):
                    return None
                return {"url": url, "status": status}
        except Exception as e:
            return {"url": url, "error": str(e)}
        return None

    def run(self):
        found = []
        tasks = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for proto in ["http", "https"]:
            print(f"[*] [Module: {colored_module}] Getting baseline for {proto.upper()}...")
            self.baseline_bodies[proto] = self.get_baseline(proto)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for path in self.paths:
                for protocol in ["http", "https"]:
                    tasks.append(executor.submit(self.check_path, protocol, path))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    found.append(result)
                    colored_url = self.printer.color_text(result.get("url", ""), "yellow")
                    if "status" in result:
                        status_color = "green" if result["status"] == 200 else "red"
                        colored_status = self.printer.color_text(str(result["status"]), status_color)
                        print(f"[*] [Module: {colored_module}] [URL: {colored_url}] [Status: {colored_status}]")
                    elif "error" in result and self.verbose:
                        colored_error = self.printer.color_text(result["error"], "red")
                        print(f"[!] [Module: {colored_module}] [URL: {colored_url}] [Error: {colored_error}]")

        if not found:
            print(f"[*] [Module: {colored_module}] No admin panel or directories exposed.")
        return found if found else [{"admin_panel_found": False}]

def scan(args=None):
    return EnumerationDirectoryScanner(args).run()
