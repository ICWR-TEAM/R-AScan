![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)
![Issues](https://img.shields.io/badge/issues-open-important.svg)

# R-AScan (Rusher Automatic Scanner)

R-AScan is a modular, multithreaded vulnerability scanner framework written in Python. It automatically loads and runs all scanning modules located in the scanners/ directory.

---

## Features

* Modular scanner structure (easy to extend)
* Multithreaded scanning for improved speed
* Automatic update of scanner modules from GitHub
* JSON output for easy integration
* Includes scanners for common web vulnerabilities:

  * Local File Inclusion (LFI)
  * Remote Code Execution (RCE)
  * Server-Side Request Forgery (SSRF)
  * Security headers
  * Sensitive file exposure
  * XSS, open redirect, admin panel finder
  * And more

---

## Requirements

* Python 3.8 or newer
* `requests` library

To install the required package:

```
python3 -m pip install -r requirements.txt
```

---

## Usage

```
python3 main.py -x <target> -t <threads> -o <output_path> --update
```

Examples:

```
python3 main.py -x example.com
python3 main.py -x 192.168.1.1 -t 10
python3 main.py --update
```

Arguments:

* `-x` or `--target` — Target domain or IP address
* `-t` or `--threads` — Number of threads (default: 5)
* `-o` or `--output` — Path to save JSON results (optional)
* `--update` — Only update scanner modules from GitHub and exit

---

## Output

The scan results are saved in a JSON file named like:

```
scan_output-<target>.json
```

Or at a custom path if `-o` is specified.

---

## Adding Your Own Module

To create a new scan module:

1. Create a Python file in the `scanners/` folder (for example: `my_scan.py`)
2. Define a `scan(args)` function that returns a dictionary or list

Example module:

```python
import requests

def scan(args):
    target = args.target
    url = f"http://{target}/test"
    response = requests.get(url, timeout=10)
    return {
        "url": url,
        "status_code": response.status_code
    }
```

The scanner will automatically load this module and run the `scan` function.

---

## Updating Scanners

To fetch the latest scanner modules from the GitHub repository:

```
python3 main.py --update
```

This will download and replace `.py` files in the `scanners/` directory.

---

## License

This project is released under the MIT License. Developed by HarshXor (incrustwerush.org).
