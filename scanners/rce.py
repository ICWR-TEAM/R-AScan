import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class RCEScanner:
    def __init__(self):
        self.payloads = {
            ';echo rce_test_123': 'rce_test_123',
            '|echo rce_test_456': 'rce_test_456',
            '`echo rce_test_789`': 'rce_test_789'
        }

    def scan(self, target):
        results = []
        schemes = ["https", "http"]

        for scheme in schemes:
            for payload, marker in self.payloads.items():
                try:
                    url = f"{scheme}://{target}/?cmd={payload}"
                    response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
                    if response.status_code == 200 and marker in response.text:
                        results.append({"vulnerable": True, "payload": url, "marker": marker})
                        return results
                except requests.RequestException as e:
                    results.append({"error": str(e)})
            if results and any(r.get("vulnerable") for r in results):
                break

        return results if results else [{"vulnerable": False}]

def scan(args=None):
    return RCEScanner().scan(args.target)
