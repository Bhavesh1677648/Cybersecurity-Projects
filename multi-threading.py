import socket
import threading

print_lock = threading.Lock()  # Prevents jumbled prints

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
    else:
        print("\n[-] No open ports found in the given range.")

if __name__ == "__main__":
    target_host = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))

    port_scan(target_host, start, end)
