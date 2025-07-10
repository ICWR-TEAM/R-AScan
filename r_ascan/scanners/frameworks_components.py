import requests, os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class FrameworksComponents:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = args.verbose
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        colored_module = self.printer.color_text(self.module_name, "cyan")
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            headers = r.headers
            x_powered = headers.get("X-Powered-By", "")
            x_generator = headers.get("X-Generator", "")

            if x_powered or x_generator:
                if x_powered:
                    colored_key = self.printer.color_text("X-Powered-By", "yellow")
                    print(f"[*] [Module: {colored_module}] {colored_key}: {x_powered}")
                if x_generator:
                    colored_key = self.printer.color_text("X-Generator", "yellow")
                    print(f"[*] [Module: {colored_module}] {colored_key}: {x_generator}")
            else:
                print(f"[*] [Module: {colored_module}] No framework headers detected.")

            return {
                "x-powered-by": x_powered,
                "x-generator": x_generator
            }
        except Exception as e:
            if self.verbose:
                colored_error = self.printer.color_text(str(e), "red")
                print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
            return {"error": str(e)}

def scan(args=None):
    return FrameworksComponents(args).scan()
