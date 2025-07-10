import requests
import re
import os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class ContentLeak:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def run(self):
        try:
            r = requests.get(f"http://{self.target}", headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            comments = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
            colored_module = self.printer.color_text(self.module_name, "cyan")
            if comments:
                print(f"[*] [Module: {colored_module}] Found {len(comments)} HTML comments.")
                for i, comment in enumerate(comments[:5]):
                    colored_comment = self.printer.color_text(comment.strip(), "yellow")
                    print(f"[*] [Module: {colored_module}] [Comment {i+1}: {colored_comment}]")
            else:
                print(f"[*] [Module: {colored_module}] No HTML comments found.")
            return {"comments": comments[:5]}
        except Exception as e:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            colored_error = self.printer.color_text(str(e), "red")
            print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
            return {"error": str(e)}

def scan(args=None):
    return ContentLeak(args).run()
