import requests
import os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class DeploymentConfig:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            text = r.text.lower()
            configs = []
            if "debug" in text: configs.append("Debug")
            if "staging" in text: configs.append("Staging")
            if "production" in text: configs.append("Production")

            colored_module = self.printer.color_text(self.module_name, "cyan")
            if configs:
                for config in configs:
                    colored_config = self.printer.color_text(config, "yellow")
                    print(f"[*] [Module: {colored_module}] [Detected: {colored_config}]")
            else:
                print(f"[*] [Module: {colored_module}] No deployment config keywords found.")
            return {"deployment": configs}
        except Exception as e:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            colored_error = self.printer.color_text(str(e), "red")
            print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
            return {"error": str(e)}

def scan(args=None):
    return DeploymentConfig(args).scan()
