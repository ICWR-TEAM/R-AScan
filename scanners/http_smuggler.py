import socket, ssl, os, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import DEFAULT_TIMEOUT, HTTP_SMUGGLING_PAYLOAD, DIRECTORIES
from module.other import Other

class HTTPSmugglingScanner:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.verbose = args.verbose
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

    def scan_payload(self, payload_obj, port, use_ssl, path):
        name = payload_obj.get("name", "Unnamed")
        raw_template = payload_obj.get("raw", "")
        raw_built = raw_template.replace("{host}", self.target).replace("{path}", path)
        response = self.send_raw(raw_built, port, use_ssl)
        status_line = response.splitlines()[0] if "HTTP" in response else "NO RESPONSE"
        valid = self.strict_validation(response, status_line)
        proto = "HTTPS" if use_ssl else "HTTP"
        prefix = "[+]" if valid else "[*]"

        if self.verbose or valid:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            colored_status = self.printer.color_text(status_line, "red" if valid else "green")
            colored_name = self.printer.color_text(name, "yellow")
            colored_path = self.printer.color_text(path, "magenta")
            print(f"{prefix} [Module: {colored_module}] [Proto: {proto}] [Name: {colored_name}] [Path: {colored_path}] [Status: {colored_status}]")

        return {
            "protocol": proto,
            "payload_name": name,
            "path": path,
            "status_line": status_line,
            "anomaly": valid
        }

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
