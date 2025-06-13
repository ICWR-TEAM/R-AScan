![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)
![Issues](https://img.shields.io/badge/issues-open-important.svg)

## R-AScan (Rusher Automatic Scanner)

R-AScan is a modular, multithreaded vulnerability scanner framework written in Python. It automatically loads and runs all scanning modules located in the `scanners/` directory.

### Features

* Threaded execution for speed
* Modular scanner structure (easily extendable)
* JSON output
* Includes scanners for common web vulnerabilities:

  * Local File Inclusion (LFI)
  * Remote Code Execution (RCE)
  * Server-Side Request Forgery (SSRF)
  * Security headers
  * Sensitive file exposure
  * XSS, open redirect, admin panel finder
  * Etc.

### Requirements

* Python 3.8+
* `requests` module

```bash
python3 -m pip install -r requirements.txt
```

### Usage

```bash
python3 main.py -x <target> -t <threads>
```

**Examples:**

```bash
python3 main.py -x example.com
python3 main.py -x 192.168.1.1 -t 10
```

### Output

Results are saved to `scan_output.json` after execution.

### Add Your Own Module

To add a new scan module:

1. Create a Python file in `scanners/` (e.g. `my_scan.py`)
2. Define a `scan(args)` function that returns a dictionary or list
3. Use shared configs from `config.py` (e.g. HTTP headers, timeout)

**Example template:**

```python
import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class MyScanner:
    def scan(self, target):
        url = f"http://{target}/something"
        response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
        return {"status": response.status_code}

def scan(args=None):
    return MyScanner().scan(args.target)
```
