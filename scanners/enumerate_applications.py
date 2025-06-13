import socket

class EnumerateApplications:
    COMMON_PORTS = [80, 443, 8080, 8443, 8000]

    def __init__(self, target):
        self.target = target

    def scan_port(self, port):
        try:
            socket.create_connection((self.target, port), timeout=2)
            return True
        except:
            return False

    def scan(self):
        open_ports = [port for port in self.COMMON_PORTS if self.scan_port(port)]
        return {"open_ports": open_ports}

def scan(args=None):
    return EnumerateApplications(args.target).scan()
