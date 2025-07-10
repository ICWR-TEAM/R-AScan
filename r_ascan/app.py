print(r"""
$$$$$$$\           $$$$$$\   $$$$$$\                               
$$  __$$\         $$  __$$\ $$  __$$\                              
$$ |  $$ |        $$ /  $$ |$$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  
$$$$$$$  |$$$$$$\ $$$$$$$$ |\$$$$$$\  $$  _____|\____$$\ $$  __$$\ 
$$  __$$< \______|$$  __$$ | \____$$\ $$ /      $$$$$$$ |$$ |  $$ |
$$ |  $$ |        $$ |  $$ |$$\   $$ |$$ |     $$  __$$ |$$ |  $$ |
$$ |  $$ |        $$ |  $$ |\$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |
\__|  \__|        \__|  \__| \______/  \_______|\_______|\__|  \__|
===================================================================
[+] R-AScan (Rusher Automatic Scan) | HarshXor - incrustwerush.org
===================================================================
""")

import sys
import json
import warnings
import argparse
import importlib.util
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.module.other import Other

warnings.filterwarnings("ignore")
sys.dont_write_bytecode = True

class RAScan:
    def __init__(self, args=None, scanner_dir="./"):
        self.args = args
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.scanner_dir = Path(__file__).parent / scanner_dir
        self.module_dir = Path(__file__).parent / "scanners/"
        self.final_result = {"result": []}

    def update_scanners_from_github(self):
        print("[*] [Update Scanners]")
        base_url = "https://api.github.com/repos/ICWR-TEAM/R-AScan/contents/r_ascan?ref=pypi-release"

        def fetch_and_save(remote_url, local_dir):
            try:
                resp = requests.get(remote_url, timeout=10)
                contents = resp.json()
                for item in contents:
                    item_path = local_dir / item["name"]
                    if item["type"] == "dir":
                        item_path.mkdir(parents=True, exist_ok=True)
                        fetch_and_save(item["url"], item_path)
                    elif item["name"]:
                        code = requests.get(item["download_url"], timeout=10).text
                        item_path.write_text(code, encoding="utf-8")
                        print(f"[+] [Downloaded: {item_path.relative_to(self.scanner_dir.parent)}]")
            except Exception as e:
                print(f"[!] Error updating from {remote_url}: {e}")

        fetch_and_save(base_url, self.scanner_dir)

    def discover_modules(self):
        return [f for f in self.module_dir.rglob("*.py") if not f.name.startswith("__")]

    def load_module(self, file_path):
        module_name = file_path.stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module_name, module

    def scan_module(self, file_path):
        try:
            module_name, module = self.load_module(file_path)
            colored_module = Other().color_text(module_name, "cyan")
            print(f"[*] [Module: {colored_module}] [Started Scan]")
            if hasattr(module, "scan"):
                result = module.scan(self.args)
                if self.args.verbose:
                    print(f"[*] [Module: {module_name}]\n└─  Result: \n{json.dumps(result, indent=4)}")
                return {module_name: result}
            else:
                print(f"[!] [Skipping {module_name} — no 'scan(target)' function found.]")
        except Exception as e:
            print(f"[-] [Error in {file_path.name}: {e}]")
        return None

    def run_all(self):
        if self.args.update:
            self.update_scanners_from_github()
            print("[*] [Update complete]")
            
            if not self.args.target:
                return

        colored_target = Other().color_text(self.target, "yellow")
        print(f"[*] [Starting scan on: {colored_target}]")
        modules = self.discover_modules()

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {executor.submit(self.scan_module, mod): mod for mod in modules}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.final_result["result"].append(result)

        output_path = (
            self.args.output
            if self.args.output else
            Path.cwd() / f"scan_output-{self.args.target}.json"
        )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.final_result, f, indent=2)

        if self.args.optimize:
            try:
                from r_ascan.module import ml_optimizer
                print("[*] [ML Optimizer] Running post-scan analysis...")
                ml_optimizer.scan(self.args)
            except Exception as e:
                print(f"[!] [ML Optimizer] Failed to run: {e}")

        print(f"[*] [Scan complete. Results saved to '{output_path}']")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-x", "--target",
        help="Target host (domain or IP)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=5,
        help="Number of threads to use (default: 5)"
    )
    parser.add_argument(
        "-o", "--output", type=str,
        help="Custom output file path (optional)"
    )
    parser.add_argument(
        "-p", "--port", type=str,
        help="Custom PORT HTTP/S (optional)"
    )
    parser.add_argument(
        "--path", type=str,
        help="Custom PATH URL HTTP/S (optional)"
    )
    parser.add_argument(
        "--update", action="store_true",
        help="Only update scanner modules without scanning"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Verbose detail log"
    )
    parser.add_argument(
        "--optimize", action="store_true",
        help="Optimize result with machine learning"
    )
    args = parser.parse_args()
    
    if not args.update and not args.target:
        print("[-] [A target must be specified unless the --update option is used]\n")
        parser.print_help()
        exit()

    scanner = RAScan(args)
    scanner.run_all()
