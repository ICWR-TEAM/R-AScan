import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from module.other import Other

class EnumerateApplications:
    COMMON_PORTS = [80, 443, 8080, 8443, 8000]

    def __init__(self, args):
        self.target = args.target
        self.thread = getattr(args, "threads", 5)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan_port(self, port):
        try:
            socket.create_connection((self.target, port), timeout=2)
            return port
        except:
            return None

    def scan(self):
        open_ports = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.COMMON_PORTS}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    colored_port = self.printer.color_text(str(port), "yellow")
                    print(f"[*] [Module: {colored_module}] [Open Port: {colored_port}]")
                    open_ports.append(port)

        if not open_ports:
            print(f"[*] [Module: {colored_module}] No open common web ports found.")

        return {"open_ports": open_ports}

def scan(args=None):
    return EnumerateApplications(args).scan()
