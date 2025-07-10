import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class EntryPoints:
    PATHS = ["/login", "/admin", "/dashboard", "/user", "/account", "/auth"]
    PROTOCOLS = ["http", "https"]

    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.max_workers = getattr(args, "threads", 5)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def check_path(self, protocol, path):
        url = f"{protocol}://{self.target}{path}"
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            if r.status_code in [200, 401, 403]:
                colored_path = self.printer.color_text(path, "yellow")
                colored_status = self.printer.color_text(str(r.status_code), "green" if r.status_code == 200 else "red")
                colored_protocol = self.printer.color_text(protocol.upper(), "magenta")
                colored_module = self.printer.color_text(self.module_name, "cyan")
                print(f"[*] [Module: {colored_module}] [Protocol: {colored_protocol}] [Path: {colored_path}] [Status: {colored_status}]")
                return f"{protocol}://{self.target}{path}"
        except:
            return None

    def run(self):
        found = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.check_path, proto, path): (proto, path)
                for proto in self.PROTOCOLS
                for path in self.PATHS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        colored_module = self.printer.color_text(self.module_name, "cyan")
        if not found:
            print(f"[*] [Module: {colored_module}] No entry points found.")

        return {"entry_points": found}

def scan(args=None):
    return EntryPoints(args).run()
