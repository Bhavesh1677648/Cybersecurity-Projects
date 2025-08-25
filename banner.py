import socket
import threading

print_lock = threading.Lock()

# Known risky ports and their warnings
RISKY_PORTS = {
    21: "FTP may allow anonymous login (insecure).",
    22: "SSH exposed – secure with strong credentials.",
    23: "Telnet is insecure (plain text).",
    25: "SMTP open – may allow spam relay.",
    53: "DNS server exposed – risk of DNS attacks.",
    80: "HTTP (unencrypted web traffic).",
    110: "POP3 email service – use secure alternatives.",
    139: "NetBIOS service – can reveal sensitive info.",
    143: "IMAP email service – may leak data.",
    445: "SMB – vulnerable to ransomware attacks.",
    3306: "MySQL database open – risk of data theft.",
    3389: "RDP – targeted for remote exploits.",
    8080: "HTTP alternative – check for weak admin panels."
}

def grab_banner(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "No banner returned"
    except:
        return "Banner grab failed"

def scan_port(target, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(target, port)
            with print_lock:
                print(f"[OPEN] Port {port} → {banner}")
                if port in RISKY_PORTS:
                    print(f"   ⚠️  Warning: {RISKY_PORTS[port]}")
            open_ports[port] = banner
        s.close()
    except:
        pass

def port_scan(target, start_port, end_port):
    print(f"\n[+] Scanning target: {target}")
    print(f"[+] Port range: {start_port}-{end_port}\n")

    open_ports = {}
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port, open_ports))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if open_ports:
        print("\n[+] Scan complete. Open ports with banners:")
        for p, banner in open_ports.items():
            print(f"   → Port {p}: {banner}")
            if p in RISKY_PORTS:
                print(f"     ⚠️  Security Warning: {RISKY_PORTS[p]}")
    else:
        print("\n[-] No open ports found in the given range.")

if __name__ == "__main__":
    target_host = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))

    port_scan(target_host, start, end)
