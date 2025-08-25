import socket
import threading
from datetime import datetime

print_lock = threading.Lock()

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
            open_ports[port] = (banner, RISKY_PORTS.get(port, None))
        s.close()
    except:
        pass

def save_report(target, open_ports, report_type="txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_report_{timestamp}.{report_type}"

    if report_type == "txt":
        with open(filename, "w", encoding="utf-8") as f:   # ✅ UTF-8 fix
            f.write(f"Port Scan Report for {target}\n")
            f.write(f"Generated on: {datetime.now()}\n\n")
            if open_ports:
                for port, (banner, warning) in open_ports.items():
                    f.write(f"[OPEN] Port {port} → {banner}\n")
                    if warning:
                        f.write(f"   ⚠️  {warning}\n")
            else:
                f.write("No open ports found.\n")

    elif report_type == "html":
        with open(filename, "w", encoding="utf-8") as f:   # ✅ UTF-8 fix
            f.write("<html><head><title>Port Scan Report</title></head><body>")
            f.write(f"<h2>Port Scan Report for {target}</h2>")
            f.write(f"<p>Generated on: {datetime.now()}</p><hr>")
            if open_ports:
                f.write("<ul>")
                for port, (banner, warning) in open_ports.items():
                    f.write(f"<li><b>Port {port}</b> → {banner}")
                    if warning:
                        f.write(f"<br><span style='color:red;'>⚠️ {warning}</span>")
                    f.write("</li>")
                f.write("</ul>")
            else:
                f.write("<p>No open ports found.</p>")
            f.write("</body></html>")

    print(f"\n[+] Report saved as {filename}")

def port_scan(target, start_port, end_port, report_type="txt"):
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
        for p, (banner, warning) in open_ports.items():
            print(f"   → Port {p}: {banner}")
            if warning:
                print(f"     ⚠️  Security Warning: {warning}")
    else:
        print("\n[-] No open ports found in the given range.")

    save_report(target, open_ports, report_type)

if __name__ == "__main__":
    target_host = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))
    report_choice = input("Save report as TXT or HTML? (txt/html): ").strip().lower()

    if report_choice not in ["txt", "html"]:
        report_choice = "txt"  # default fallback

    port_scan(target_host, start, end, report_choice)
