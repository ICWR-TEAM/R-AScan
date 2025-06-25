import socket, ssl, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import DEFAULT_TIMEOUT, HTTP_SMUGGLING_PAYLOAD
from module.other import Other

class HTTPSmugglingScanner:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.port = 443 if args.ssl else 80
        self.use_ssl = args.ssl
        self.verbose = args.verbose
        self.threads = args.threads
        self.payloads = open(HTTP_SMUGGLING_PAYLOAD).read().split("\n\n")
        self.printer = Other()
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]

    def send_raw(self, raw_data):
        host = self.target
        try:
            sock = socket.create_connection((host, self.port), timeout=DEFAULT_TIMEOUT)
            if self.use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw_data.encode())
            response = sock.recv(8192).decode(errors="ignore")
            sock.close()
            return response
        except Exception as e:
            return f"ERROR: {e}"

    def scan(self):
        results = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        def scan_payload(payload):
            built = payload.format(host=self.target)
            response = self.send_raw(built)
            status_line = response.splitlines()[0] if "HTTP" in response else "NO RESPONSE"
            suspicious = any(x in response.lower() for x in ["chunk", "unexpected", "error", "malformed", "smuggl"])
            is_anomaly = suspicious or "HTTP/1.1 4" in status_line or "HTTP/1.1 5" in status_line

            prefix = "[+]" if is_anomaly else "[*]"
            if self.verbose or is_anomaly:
                colored_status = self.printer.color_text(status_line, "red" if is_anomaly else "green")
                print(f"{prefix} [Module: {colored_module}] [Payload: {payload[:10]}...] [Status: {colored_status}]")

            return {
                "payload": payload[:30] + "...",
                "status_line": status_line,
                "anomaly": is_anomaly
            }

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = [executor.submit(scan_payload, p) for p in self.payloads if p.strip()]
            for future in as_completed(tasks):
                results.append(future.result())

        return {"http_smuggling_results": results}

def scan(args=None):
    return HTTPSmugglingScanner(args).scan()
