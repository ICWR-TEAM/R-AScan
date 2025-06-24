import socket, os
from module.other import Other

class ServiceEnumerator:
    COMMON_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP-ALT"
    }

    def __init__(self, target):
        self.target = target
        self.open_services = {}
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def grab_banner(self, port):
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.target, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()
            return banner
        except:
            return ""

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                banner = self.grab_banner(port)
                service = self.COMMON_SERVICES.get(port, "Unknown")
                self.open_services[port] = {
                    "service": service,
                    "banner": banner if banner else "No banner"
                }
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_port = self.printer.color_text(str(port), "yellow")
                colored_service = self.printer.color_text(service, "magenta")
                print(f"[*] [Module: {colored_module}] [Open Port: {colored_port}] [Service: {colored_service}]")
            sock.close()
        except Exception as e:
            pass

    def scan_all(self):
        for port in self.COMMON_SERVICES.keys():
            self.scan_port(port)
        return self.open_services

def scan(args=None):
    enumerator = ServiceEnumerator(args.target)
    results = enumerator.scan_all()
    return {"open_services": results}
