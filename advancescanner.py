import socket
import datetime

# =====================
# Advanced Service Detection
# =====================
def detect_service(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        # Send protocol-specific probes
        if port == 80 or port == 8080:   # HTTP
            s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:   # FTP
            s.send(b"HELP\r\n")
        elif port == 25:   # SMTP
            s.send(b"HELO test.com\r\n")
        elif port == 22:   # SSH
            # SSH usually sends banner first
            pass
        else:
            s.send(b"\r\n")

        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        return banner if banner else "Unknown service/version"
    except:
        return "Service detection failed"

# =====================
# Port Scanner with Service Detection
# =====================
def port_scan(target, start_port, end_port):
    open_ports = {}
    print(f"\n[+] Scanning {target} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                service_info = detect_service(target, port)
                print(f"[OPEN] Port {port} → {service_info}")
                open_ports[port] = service_info
            s.close()
        except:
            pass

    return open_ports

# =====================
# Save Report
# =====================
def save_report(target, open_ports):
    filename = f"scan_report_stage12_{target}.txt"
    with open(filename, "w") as f:
        f.write(f"Port Scan Report (with Service Detection) for {target}\n")
        f.write(f"Generated on: {datetime.datetime.now()}\n\n")

        for port, service in open_ports.items():
            f.write(f"[OPEN] Port {port} → {service}\n")

    print(f"\n[+] Report saved as {filename}")

# =====================
# Main
# =====================
if __name__ == "__main__":
    target = input("Enter target host (IP or domain): ").strip()
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    open_ports = port_scan(target, start_port, end_port)
    save_report(target, open_ports)
