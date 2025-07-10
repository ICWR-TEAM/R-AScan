import requests
import os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class Technologies:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        techs = []
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            text = r.text.lower()
            if "php" in text: techs.append("PHP")
            if "wordpress" in text: techs.append("WordPress")
            if "react" in text: techs.append("React")
            if "django" in text: techs.append("Django")

            if techs:
                for t in techs:
                    print(f"[+] [Module: {self.printer.color_text(self.module_name, 'cyan')}] Detected technology: {self.printer.color_text(t, 'yellow')}")
            else:
                print(f"[*] [Module: {self.printer.color_text(self.module_name, 'cyan')}] No known technologies detected.")

            return {"technologies": techs}
        except Exception as e:
            return {"error": str(e)}

def scan(args=None):
    return Technologies(args).scan()
