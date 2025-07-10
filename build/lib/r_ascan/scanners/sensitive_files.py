import requests, os, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT, SENSITIVE_FILES
from r_ascan.module.other import Other

class SensitiveFileScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.thread = args.threads
        self.paths = open(SENSITIVE_FILES, "r").read().splitlines()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.baseline_body = None

    def get_baseline(self):
        rand_id = random.randint(100000, 999999)
        random_path = f"/__nonexistent_{rand_id}"
        url = f"http://{self.target}{random_path}"
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            return response.text.strip()
        except Exception:
            return ""

    def is_similar_to_baseline(self, content):
        if not self.baseline_body or not content:
            return False
        content = content.strip()
        if abs(len(content) - len(self.baseline_body)) < 30:
            head1 = self.baseline_body[:50].lower()
            head2 = content[:50].lower()
            return head1 == head2
        return False

    def check_file(self, path):
        url = f"http://{self.target}{path}"
        try:
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            if response.status_code != 200:
                return None
            if self.is_similar_to_baseline(response.text):
                return None
            keywords = ["password", "user", "host", "env", "config", "key", "secret"]
            if self.verbose or any(k in response.text.lower() for k in keywords):
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
        print(f"[*] [Module: {colored_module}] Getting baseline response...")
        self.baseline_body = self.get_baseline()

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            futures = {executor.submit(self.check_file, path): path for path in self.paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    exposed.append(result)
                    colored_file = self.printer.color_text(result["file"], "yellow")
                    if "status" in result:
                        code = result["status"]
                        colored_status = self.printer.color_text(code, "green" if code == 200 else "red")
                        print(f"[*] [Module: {colored_module}] [File: {colored_file}] [Status Code: {colored_status}]")
                    elif "error" in result and self.verbose:
                        colored_error = self.printer.color_text(result["error"], "red")
                        print(f"[!] [Module: {colored_module}] [File: {colored_file}] [Error: {colored_error}]")

        if not exposed:
            print(f"[*] [Module: {colored_module}] No sensitive files exposed.")
        return exposed if exposed else [{"exposed_files": False}]

def scan(args=None):
    return SensitiveFileScanner(args).scan()
