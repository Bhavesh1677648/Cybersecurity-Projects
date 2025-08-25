import socket
import threading
import queue
import datetime

# =====================
# Common Ports (Top 1000 - shortened for demo)
# =====================
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 139, 143, 161, 389, 443,
    445, 514, 587, 993, 995, 1080, 1433, 1521, 1723, 3306, 3389, 5060, 8080
]

# =====================
# TCP Banner Grab
# =====================
def tcp_scan(host, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        conn = s.connect_ex((host, port))
        if conn == 0:
            try:
                s.send(b"Hello\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "Banner grab failed"
            results.append((port, "TCP", banner))
        s.close()
    except:
        pass

# =====================
# UDP Scan
# =====================
def udp_scan(host, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"\x00", (host, port))  # dummy packet
        try:
            data, _ = s.recvfrom(1024)
            banner = data.decode(errors="ignore").strip()
        except socket.timeout:
            banner = "No response (open|filtered)"
        results.append((port, "UDP", banner))
        s.close()
    except:
        pass

# =====================
# Main Scanner
# =====================
def port_scan(host, start_port, end_port, mode="full"):
    results = []
    threads = []

    if mode == "fast":
        ports = COMMON_PORTS
    else:
        ports = range(start_port, end_port + 1)

    print(f"\n[+] Scanning target: {host}")
    print(f"[+] Mode: {mode.upper()}")
    print(f"[+] Port range: {start_port}-{end_port}\n")

    for port in ports:
        t = threading.Thread(target=tcp_scan, args=(host, port, results))
        t.start()
        threads.append(t)

        # UDP scanning only on selected ports (lightweight)
        if port in [53, 67, 68, 123, 161]:
            t_udp = threading.Thread(target=udp_scan, args=(host, port, results))
            t_udp.start()
            threads.append(t_udp)

    for t in threads:
        t.join()

    # Sort by port
    results.sort(key=lambda x: x[0])

    # Display results
    for port, proto, banner in results:
        print(f"[OPEN] {proto} Port {port} → {banner}")

    # Save report
    save_report(host, results)

# =====================
# Save Report
# =====================
def save_report(host, results):
    filename = f"scan_report_{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Port Scan Report for {host}\n")
        f.write(f"Generated on: {datetime.datetime.now()}\n\n")
        for port, proto, banner in results:
            f.write(f"[OPEN] {proto} Port {port} → {banner}\n")
    print(f"\n[+] Report saved as {filename}")

# =====================
# Run
# =====================
if __name__ == "__main__":
    target = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))
    scan_mode = input("Choose mode (full/fast): ").strip().lower()

    port_scan(target, start, end, scan_mode)
