import requests, os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class HostingEnvironment:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            text = r.text.lower()
            env = []
            if "cloudflare" in text: env.append("Cloudflare")
            if "amazonaws" in text: env.append("AWS")
            if "azure" in text: env.append("Azure")

            if env:
                for e in env:
                    colored_env = self.printer.color_text(e, "yellow")
                    print(f"[*] [Module: {colored_module}] [Detected: {colored_env}]")
            else:
                print(f"[*] [Module: {colored_module}] No cloud hosting environment detected.")

            return {"hosting": env}
        except Exception as e:
            colored_error = self.printer.color_text(str(e), "red")
            print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
            return {"error": str(e)}

def scan(args=None):
    return HostingEnvironment(args).scan()
