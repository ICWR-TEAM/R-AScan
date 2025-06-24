import socket
import os
from module.other import Other

class EnumerateApplications:
    COMMON_PORTS = [80, 443, 8080, 8443, 8000]

    def __init__(self, target):
        self.target = target
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def scan_port(self, port):
        try:
            socket.create_connection((self.target, port), timeout=2)
            return True
        except:
            return False

    def scan(self):
        open_ports = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for port in self.COMMON_PORTS:
            if self.scan_port(port):
                colored_port = self.printer.color_text(str(port), "yellow")
                print(f"[*] [Module: {colored_module}] [Open Port: {colored_port}]")
                open_ports.append(port)

        if not open_ports:
            print(f"[*] [Module: {colored_module}] No open common web ports found.")

        return {"open_ports": open_ports}

def scan(args=None):
    return EnumerateApplications(args.target).scan()
