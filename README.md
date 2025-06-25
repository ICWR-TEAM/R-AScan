![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)
![Issues](https://img.shields.io/badge/issues-open-important.svg)

# R-AScan (Rusher Automatic Scanner)

## Overview

R-AScan is a modular, multithreaded vulnerability scanner framework written in Python. It dynamically loads all `.py` scanner modules in the `scanners/` directory and executes them against a target. Each module returns structured output and is saved to a JSON file for analysis.

![IMG-20250624-WA0064](https://github.com/user-attachments/assets/622d7ff2-869b-4a90-9263-d4ecc7ecf75d)


## Features

- Modular architecture (drop-in `.py` modules)
- Multithreaded execution using thread pool
- Auto-update scanner modules from GitHub
- JSON output format
- CLI-based execution with multiple options
- Includes scanners for:
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  - Cross-Site Scripting (XSS)
  - Server-Side Request Forgery (SSRF)
  - SQL Injection (SQLi)
  - Open Redirect
  - Security Headers
  - Sensitive Files
  - Fingerprinting
  - Admin Panel Finder
  - Rate Limiting
  - SSTI
  - LDAP Injection
  - and others

## Requirements

- Python 3.8 or newer
- `requests` library

Install dependencies:

```bash
pip install -r requirements.txt
````

## Usage

```bash
python3 main.py -x <target> [options]
```

```
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

[-] [A target must be specified unless the --update option is used]

usage: R-AScan.py [-h] [-x TARGET] [-t THREADS] [-o OUTPUT] [--update] [--verbose]

options:
  -h, --help            show this help message and exit
  -x, --target TARGET   Target host (domain or IP)
  -t, --threads THREADS
                        Number of threads to use (default: 5)
  -o, --output OUTPUT   Custom output file path (optional)
  --update              Only update scanner modules without scanning
  --verbose             Verbose detail log
```

### Examples

```bash
python3 main.py -x example.com
python3 main.py -x 192.168.1.1 -t 10 -o output.json
python3 main.py --update
```

### Arguments

* `-x`, `--target` — Target domain or IP address (required unless using `--update`)
* `-t`, `--threads` — Number of threads (default: 5)
* `-o`, `--output` — Path to save JSON result (optional)
* `--update` — Update scanner modules from GitHub and exit
* `--verbose` — Print detailed output from each module

## Output

The scan result will be saved as:

```
scan_output-<target>.json
```

If the `-o` option is specified, it will be saved to the given custom path.

Each scanner module contributes a dictionary entry in the JSON output, grouped under the `result` key.

## Writing a Custom Module

1. Create a new Python file in `scanners/`, for example `my_scan.py`
2. Define a function `scan(args)` that returns a dictionary or list
3. Access the target using `args.target`

### Example

```python
import requests

def scan(args):
    url = f"http://{args.target}/test"
    try:
        response = requests.get(url, timeout=10)
        return {
            "url": url,
            "status_code": response.status_code
        }
    except Exception as e:
        return {"error": str(e)}
```

The main framework will automatically discover and execute this module.

## Updating Modules

To update scanner modules directly from the GitHub repository:

```bash
python3 main.py --update
```

All `.py` files in the `scanners/` directory will be downloaded and replaced.

## License

This project is licensed under the MIT License.

Developed by HarshXor — [https://incrustwerush.org](https://incrustwerush.org)
