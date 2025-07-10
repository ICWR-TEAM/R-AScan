import requests, os
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class WebFingerprintScanner:
    def __init__(self, args):
        self.target = f"{args.target}:{args.port}" if args.port else args.target
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
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan(self):
        target = self.target
        colored_module = self.printer.color_text(self.module_name, "cyan")
        colored_target = self.printer.color_text(target, "yellow")
        try:
            url = f"http://{target}"
            response = requests.get(url, headers=HTTP_HEADERS, timeout=DEFAULT_TIMEOUT)
            headers = response.headers
            fingerprints = {h: headers[h] for h in self.fingerprint_headers if h in headers}
            tech_insight = self._analyze_headers(fingerprints)

            if fingerprints:
                print(f"[*] [Module: {colored_module}] [Target: {colored_target}] Found fingerprint headers:")
                for k, v in fingerprints.items():
                    print(f"    [*] {k}: {v}")
            if tech_insight:
                print(f"[*] [Module: {colored_module}] [Target: {colored_target}] Detected technologies: {', '.join(tech_insight)}")
            else:
                print(f"[*] [Module: {colored_module}] No technology detected.")

            return {
                "target": target,
                "fingerprints": fingerprints,
                "tech_detected": tech_insight
            }

        except Exception as e:
            colored_error = self.printer.color_text(str(e), "red")
            print(f"[!] [Module: {colored_module}] [Error: {colored_error}]")
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
    return WebFingerprintScanner(args).scan()
