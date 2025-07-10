import requests, os, random
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class MetafilesLeak:
    PATHS = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/config"]

    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.baseline_body = self.get_baseline_body()

    def get_baseline_body(self):
        rand_path = f"/__nonexistent_{random.randint(100000, 999999)}.txt"
        url = f"http://{self.target}{rand_path}"
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            return r.text.strip()
        except:
            return ""

    def is_similar_to_baseline(self, content):
        if not self.baseline_body or not content:
            return False
        content = content.strip()
        if abs(len(content) - len(self.baseline_body)) < 30:
            return self.baseline_body[:50].lower() == content[:50].lower()
        return False

    def run(self):
        found = {}
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for path in self.PATHS:
            try:
                url = f"http://{self.target}{path}"
                r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
                content = r.text.strip()
                if r.status_code == 200 and content and not self.is_similar_to_baseline(content):
                    content_preview = content[:200]
                    colored_path = self.printer.color_text(path, "yellow")
                    print(f"[*] [Module: {colored_module}] [Found: {colored_path}]")
                    found[path] = content_preview
            except Exception as e:
                if self.verbose:
                    colored_error = self.printer.color_text(str(e), "red")
                    print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")

        if not found:
            print(f"[*] [Module: {colored_module}] No metafiles found.")

        return {"metafiles": found}

def scan(args=None):
    return MetafilesLeak(args).run()
