import requests
from config import HTTP_HEADERS, DEFAULT_TIMEOUT

class WebFingerprintScanner:
    def __init__(self):
        self.fingerprint_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-Runtime",
            "X-Generator",
            "Via",
            "Set-Cookie",
            "CF-RAY",
            "X-CDN",
            "X-Cache",
            "X-Amz-Cf-Id",
            "X-Turbo-Charged-By"
        ]

    def scan(self, target):
        try:
            url = f"http://{target}"
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            headers = response.headers

            fingerprints = {h: headers[h] for h in self.fingerprint_headers if h in headers}
            tech_insight = self._analyze_headers(fingerprints)

            return {
                "target": target,
                "fingerprints": fingerprints,
                "tech_detected": tech_insight
            }

        except Exception as e:
            return {"error": str(e)}

    def _analyze_headers(self, headers):
        detected = []

        if 'Server' in headers:
            server_val = headers['Server'].lower()
            if 'nginx' in server_val:
                detected.append("Nginx")
            elif 'apache' in server_val:
                detected.append("Apache")
            elif 'iis' in server_val:
                detected.append("Microsoft IIS")
            elif 'cloudflare' in server_val:
                detected.append("Cloudflare")

        if 'X-Powered-By' in headers:
            xpb = headers['X-Powered-By'].lower()
            if 'php' in xpb:
                detected.append("PHP")
            if 'asp.net' in xpb:
                detected.append("ASP.NET")
            if 'express' in xpb:
                detected.append("Node.js (Express)")
            if 'laravel' in xpb:
                detected.append("Laravel")

        if 'Set-Cookie' in headers:
            cookie_val = headers['Set-Cookie'].lower()
            if 'ci_session' in cookie_val:
                detected.append("CodeIgniter")
            if 'laravel_session' in cookie_val:
                detected.append("Laravel")
            if 'wordpress' in cookie_val:
                detected.append("WordPress")

        if 'X-Turbo-Charged-By' in headers and 'shopify' in headers['X-Turbo-Charged-By'].lower():
            detected.append("Shopify")

        return list(set(detected))

def scan(args=None):
    return WebFingerprintScanner().scan(args.target)
