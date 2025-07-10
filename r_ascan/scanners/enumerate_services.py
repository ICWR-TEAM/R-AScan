import socket, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from r_ascan.module.other import Other

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
        8080: "HTTP-ALT",
        8000: "Custom-HTTP",
        8443: "HTTPS-ALT"
    }

    def __init__(self, args):
        self.target = args.target
        self.thread = args.threads
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.results = {
            "open_ports": [],
            "open_services": {}
        }

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
                service = self.COMMON_SERVICES.get(port, "Unknown")
                banner = self.grab_banner(port)
                self.results["open_ports"].append(port)
                self.results["open_services"][port] = {
                    "service": service,
                    "banner": banner if banner else "No banner"
                }
                colored_module = self.printer.color_text(self.module_name, "cyan")
                colored_port = self.printer.color_text(str(port), "yellow")
                colored_service = self.printer.color_text(service, "magenta")
                print(f"[*] [Module: {colored_module}] [Open Port: {colored_port}] [Service: {colored_service}]")
        except:
            pass

    def scan(self):
        ports = set(self.COMMON_SERVICES.keys())
        with ThreadPoolExecutor(max_workers=self.thread) as executor:
            futures = [executor.submit(self.scan_port, port) for port in ports]
            for _ in as_completed(futures):
                pass

        if not self.results["open_ports"]:
            colored_module = self.printer.color_text(self.module_name, "cyan")
            print(f"[*] [Module: {colored_module}] No open ports or services found.")

        return self.results

def scan(args=None):
    return ServiceEnumerator(args).scan()
