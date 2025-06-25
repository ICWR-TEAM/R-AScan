import socket, ssl, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import DEFAULT_TIMEOUT, HTTP_SMUGGLING_PAYLOAD
from module.other import Other

class HTTPSmugglingScanner:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.verbose = args.verbose
        self.threads = args.threads
        self.payloads = open(HTTP_SMUGGLING_PAYLOAD).read().split("<!-- splitter -->")
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

    def scan(self):
        results = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        def scan_payload(payload, port, use_ssl):
            built = payload.format(host=self.target)
            response = self.send_raw(built, port, use_ssl)
            status_line = response.splitlines()[0] if "HTTP" in response else "NO RESPONSE"
            suspicious = any(x in response.lower() for x in ["chunk", "unexpected", "error", "malformed", "smuggl"])
            is_anomaly = suspicious or "HTTP/1.1 4" in status_line or "HTTP/1.1 5" in status_line
            proto = "HTTPS" if use_ssl else "HTTP"
            prefix = "[+]" if is_anomaly else "[*]"

            if self.verbose or is_anomaly:
                colored_status = self.printer.color_text(status_line, "red" if is_anomaly else "green")
                print(f"{prefix} [Module: {colored_module}] [Proto: {proto}] [Payload: {payload[:10]}...] [Status: {colored_status}]")

            return {
                "protocol": proto,
                "payload": payload[:30] + "...",
                "status_line": status_line,
                "anomaly": is_anomaly
            }

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            for payload in self.payloads:
                if payload.strip():
                    tasks.append(executor.submit(scan_payload, payload, 80, False))
                    tasks.append(executor.submit(scan_payload, payload, 443, True))
            for future in as_completed(tasks):
                results.append(future.result())

        return {"http_smuggling_results": results}

def scan(args=None):
    return HTTPSmugglingScanner(args).scan()
