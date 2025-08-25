import socket
import platform
import datetime

def detect_os(target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(1)
        sock.connect((target, 1))
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()
        if ttl <= 64:
            return "Linux/Unix (TTL ~64)"
        elif ttl <= 128:
            return "Windows (TTL ~128)"
        else:
            return "Unknown OS"
    except Exception:
        return "Unknown OS"

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")  # Try HTTP request
        banner = sock.recv(1024).decode(errors="ignore")
        sock.close()
        if banner.strip():
            return banner.strip().split("\n")[0]
        else:
            return "Banner grab failed"
    except Exception:
        return "Banner grab failed"

def scan_ports(target, start_port, end_port):
    open_ports = {}
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = grab_banner(target, port)
                open_ports[port] = banner
            sock.close()
        except Exception:
            pass
    return open_ports

def save_report(target, open_ports, os_guess):
    filename = f"scan_report_{target}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Port Scan Report for {target}\n")
        f.write(f"Generated on: {datetime.datetime.now()}\n\n")
        
        for port, banner in open_ports.items():
            f.write(f"[OPEN] Port {port} → {banner}\n")
            if "OpenSSH" in banner:
                f.write("   ⚠️ Detected SSH Service\n")
            elif "Apache" in banner:
                f.write("   ⚠️ Detected Apache HTTP Server\n")
            elif "Microsoft" in banner:
                f.write("   ⚠️ Detected Microsoft Service\n")

        f.write(f"\n[OS Detection] {os_guess}\n")

    print(f"[+] Report saved as {filename}")

if __name__ == "__main__":
    target = input("Enter target host (IP or domain): ")
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))

    print(f"\n[+] Scanning {target} from port {start} to {end}...\n")
    open_ports = scan_ports(target, start, end)

    os_guess = detect_os(target)

    if open_ports:
        for port, banner in open_ports.items():
            print(f"[OPEN] Port {port} → {banner}")
    else:
        print("[-] No open ports found.")

    print(f"\n[OS Detection] {os_guess}")
    save_report(target, open_ports, os_guess)
