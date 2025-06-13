import requests
import re
from urllib.parse import urlencode
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class SQLiScanner:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "'--",
            '"--',
            "'#",
            "OR 1=1",
            "') OR ('1'='1",
        ]
        self.error_patterns = [
            "you have an error in your sql syntax",
            "warning.*mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "mysql_fetch",
            "pg_query",
            "syntax error",
            "sqlstate",
        ]

    def scan(self, target):
        result = {"vulnerable": False, "details": []}
        base = target if target.startswith("http") else f"http://{target}"

        for payload in self.payloads:
            test_url = base + ("&" if "?" in base else "?") + urlencode({"id": payload})
            try:
                resp = requests.get(
                    test_url,
                    headers=HTTP_HEADERS,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
                lower_text = resp.text.lower()

                if any(re.search(pattern, lower_text) for pattern in self.error_patterns):
                    result["vulnerable"] = True
                    result["details"].append({
                        "url": resp.url,
                        "payload": payload,
                        "type": "error-based"
                    })
                    break
                elif payload in resp.text:
                    result["vulnerable"] = True
                    result["details"].append({
                        "url": resp.url,
                        "payload": payload,
                        "type": "reflected"
                    })
                    break

            except Exception as e:
                result["details"].append({"url": test_url, "error": str(e)})

        if not result["details"]:
            result["details"].append("No SQLi behavior detected")

        return result

def scan(args=None):
    return SQLiScanner().scan(args.target)
