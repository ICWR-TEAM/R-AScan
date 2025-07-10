import socket, ssl, os, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.config import DEFAULT_TIMEOUT, HTTP_SMUGGLING_PAYLOAD, DIRECTORIES
from r_ascan.module.other import Other

class HTTPSmugglingScanner:
    def __init__(self, args):
        self.args = args
        self.target = f"{args.target}:{args.port}" if args.port else args.target
        self.verbose = self.args.verbose
        self.threads = self.args.threads
        self.payloads = json.load(open(HTTP_SMUGGLING_PAYLOAD))
        self.paths = [line.strip() for line in open(DIRECTORIES) if line.strip()]
        self.printer = Other()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]

    def send_raw(self, raw_data, port, use_ssl):
        try:
            sock = socket.create_connection((self.target, port), timeout=DEFAULT_TIMEOUT)
            if use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.target)
            sock.sendall(raw_data.encode())
            response = sock.recv(8192).decode(errors="ignore")
            sock.close()
            return response
        except Exception as e:
            return f"ERROR: {e}"

    def strict_validation(self, response, status_line):
        if not response or response.startswith("ERROR"):
            return False
        if response.lower().count("http/1.1") >= 2:
            return True
        lines = response.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("HTTP/1.1 200") and i > 0:
                return True
        suspicious_keywords = ["flag", "/admin", "/dashboard", "confidential", "secret"]
        if any(key in response.lower() for key in suspicious_keywords):
            return True
        return False

    def build_curl_command(self, raw_data, use_ssl, port):
        lines = raw_data.strip().split("\r\n")
        method, path, _ = lines[0].split()
        headers = []
        body_lines = []
        header_ended = False
        for line in lines[1:]:
            if line == "":
                header_ended = True
                continue
            if not header_ended:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers.append(f"-H \"{key.strip()}: {value.strip()}\"")
            else:
                body_lines.append(line)
        proto = "https" if use_ssl else "http"
        port_part = f":{port}" if (use_ssl and port != 443) or (not use_ssl and port != 80) else ""
        url = f"{proto}://{self.target}{port_part}{path}"
        body = "\\r\\n".join(body_lines)
        return f"curl -X {method} {url} {' '.join(headers)} --data-binary $'{body}'"

    def scan_payload(self, payload_obj, port, use_ssl, path):
        name = payload_obj.get("name", "Unnamed")
        raw_template = payload_obj.get("raw", "")
        raw_built = raw_template.replace("{host}", self.target).replace("{path}", path)
        response = self.send_raw(raw_built, port, use_ssl)
        status_line = response.splitlines()[0] if "HTTP" in response else "NO RESPONSE"
        valid = self.strict_validation(response, status_line)
        proto = "HTTPS" if use_ssl else "HTTP"
        status = "Vuln" if valid else "Not Vuln"
        prefix = "[+]" if valid else "[*]"

        if self.verbose or valid:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            colored_status = self.printer.color_text(status, "green" if valid else "red")
            colored_name = self.printer.color_text(name, "yellow")
            colored_path = self.printer.color_text(path, "magenta")

            output_lines = [
                f"{prefix} [Module: {colored_module}] [Proto: {proto}] [Name: {colored_name}] [Path: {colored_path}] [Status: {colored_status}]"
            ]

            if valid:
                curl_cmd = self.build_curl_command(raw_built, use_ssl, port)
                colored_curl = self.printer.color_text(curl_cmd, "cyan")
                output_lines.append(f"\t[*] [Curl Command: {colored_curl}]")

            print("\n".join(output_lines))

        result = {
            "protocol": proto,
            "payload_name": name,
            "path": path,
            "status_line": status_line,
            "anomaly": valid
        }

        if valid:
            result["curl"] = self.build_curl_command(raw_built, use_ssl, port)

        return result

    def run(self):
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            for path in self.paths:
                for payload in self.payloads:
                    if payload.get("raw", "").strip():
                        tasks.append(executor.submit(self.scan_payload, payload, 80, False, path))
                        tasks.append(executor.submit(self.scan_payload, payload, 443, True, path))
            for future in as_completed(tasks):
                result = future.result()
                if self.verbose or result["anomaly"]:
                    results.append(result)
        return {"http_smuggling_results": results}

def scan(args=None):
    return HTTPSmugglingScanner(args).run()
