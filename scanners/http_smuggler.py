import socket, ssl, os, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import DEFAULT_TIMEOUT, HTTP_SMUGGLING_PAYLOAD, DIRECTORIES
from module.other import Other

class HTTPSmugglingScanner:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.verbose = args.verbose
        self.threads = args.threads
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

    def build_tasks(self):
        tasks = []
        for path in self.paths:
            for payload in self.payloads:
                if payload.get("raw", "").strip():
                    tasks.append((payload, 80, False, path))
                    tasks.append((payload, 443, True, path))
        return tasks

    def process_payload(self, payload_obj, port, use_ssl, path):
        name = payload_obj.get("name", "Unnamed")
        raw_template = payload_obj.get("raw", "")
        raw_built = raw_template.replace("{host}", self.target).replace("{path}", path)
        response = self.send_raw(raw_built, port, use_ssl)
        status_line = response.splitlines()[0] if "HTTP" in response else "NO RESPONSE"
        suspicious = any(x in response.lower() for x in ["chunk", "unexpected", "error", "malformed", "smuggl"])
        is_anomaly = suspicious or "HTTP/1.1 4" in status_line or "HTTP/1.1 5" in status_line
        proto = "HTTPS" if use_ssl else "HTTP"
        prefix = "+" if is_anomaly else "-"

        if self.verbose or is_anomaly:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            colored_status = self.printer.color_text(status_line, "red" if is_anomaly else "green")
            colored_name = self.printer.color_text(name, "yellow")
            colored_path = self.printer.color_text(path, "magenta")
            print(f"[{{{prefix}}}] [Module: {colored_module}] [Proto: {proto}] [Name: {colored_name}] [Path: {colored_path}] [Status: {colored_status}]")

        return {
            "protocol": proto,
            "payload_name": name,
            "path": path,
            "status_line": status_line,
            "anomaly": is_anomaly
        }

    def run(self):
        results = []
        tasks = self.build_tasks()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.process_payload, *task) for task in tasks]
            for future in as_completed(futures):
                results.append(future.result())
        return {"http_smuggling_results": results}

def scan(args=None):
    return HTTPSmugglingScanner(args).run()
