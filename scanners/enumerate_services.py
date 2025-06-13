import socket

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
                self.open_services[port] = {
                    "service": self.COMMON_SERVICES.get(port, "Unknown"),
                    "banner": banner if banner else "No banner"
                }
            sock.close()
        except:
            pass

    def scan_all(self):
        for port in self.COMMON_SERVICES.keys():
            self.scan_port(port)
        return self.open_services

def scan(args=None):
    enumerator = ServiceEnumerator(args.target)
    results = enumerator.scan_all()
    return {"open_services": results}
