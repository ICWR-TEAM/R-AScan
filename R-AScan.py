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

warnings.filterwarnings("ignore")
sys.dont_write_bytecode = True

class RAScan:
    def __init__(self, args=None, scanner_dir="scanners"):
        self.args = args
        self.scanner_dir = Path(__file__).parent / scanner_dir
        self.final_result = {"result": []}

    def update_scanners_from_github(self):
        print("[*] [Checking for updates]")
        url = "https://api.github.com/repos/ICWR-TEAM/R-AScan/contents/scanners"
        try:
            for f in requests.get(url, timeout=10).json():
                if f["name"].endswith(".py"):
                    path = self.scanner_dir / f["name"]
                    try:
                        code = requests.get(f["download_url"], timeout=10).text
                        path.write_text(code, encoding="utf-8")
                        print(f"[+] [Downloaded: {f['name']}]")
                    except Exception as e:
                        print(f"[!] Failed to download {f['name']}: {e}")
        except Exception as e:
            print(f"[!] Update error: {e}")

    def discover_modules(self):
        return [f for f in self.scanner_dir.glob("*.py") if not f.name.startswith("__")]

    def load_module(self, file_path):
        module_name = file_path.stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module_name, module

    def scan_module(self, file_path):
        try:
            module_name, module = self.load_module(file_path)
            if hasattr(module, "scan"):
                result = module.scan(self.args)
                print(f"[*] [Module: {module_name}]\n\t└─  Result: \n{json.dumps(result, indent=4)}")
                return {module_name: result}
            else:
                print(f"[!] [Skipping {module_name} — no 'scan(target)' function found.]")
        except Exception as e:
            print(f"[-] [Error in {file_path.name}: {e}]")
        return None

    def run_all(self):
        self.update_scanners_from_github()
        print(f"[*] [Starting scan on: {self.args.target}]")
        modules = self.discover_modules()

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {executor.submit(self.scan_module, mod): mod for mod in modules}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.final_result["result"].append(result)

        output_path = (
            Path(self.args.output)
            if self.args.output else
            Path(__file__).parent / f"scan_output-{self.args.target}.json"
        )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.final_result, f, indent=2)

        print(f"[*] [Scan complete. Results saved to '{output_path}']")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-x", "--target", required=True,
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

    args = parser.parse_args()
    scanner = RAScan(args)
    scanner.run_all()
