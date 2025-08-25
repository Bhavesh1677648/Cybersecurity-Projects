import socket
import datetime
import platform
import subprocess

def banner_grab(host, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "No banner"
    except:
        return "Banner grab failed"

def os_detection(host):
    try:
        # Send one ping
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", host]
        else:
            cmd = ["ping", "-c", "1", host]
        output = subprocess.check_output(cmd, universal_newlines=True)
        
        if "TTL=" in output.upper():
            ttl = int(output.upper().split("TTL=")[1].split()[0])
            if ttl <= 64:
                return f"Linux/Unix (TTL ~{ttl})"
            elif ttl <= 128:
                return f"Windows (TTL ~{ttl})"
            else:
                return f"Unknown OS (TTL ~{ttl})"
        return "OS detection failed"
    except:
        return "OS detection failed"

def save_report(target, open_ports, os_guess):
    timestamp = datetime.datetime.now()
    filename = f"scan_report_{target}.txt"
    with open(filename, "w", encoding="utf-8") as f:   # ✅ Force UTF-8
        f.write(f"Port Scan Report for {target}\n")
        f.write(f"Generated on: {timestamp}\n\n")
        
        if open_ports:
            for port, banner in open_ports.items():
                f.write(f"[OPEN] Port {port} -> {banner}\n")   # ✅ Replaced → with ->
        else:
            f.write("No open ports found.\n")
        
        f.write(f"\n[OS Detection] {os_guess}\n")
    
    print(f"\n[+] Report saved as {filename}")

def port_scan(target, start_port, end_port):
    print(f"\n[+] Scanning {target} from port {start_port} to {end_port}...\n")
    open_ports = {}
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                banner = banner_grab(target, port)
                print(f"[OPEN] Port {port} -> {banner}")
                open_ports[port] = banner
            s.close()
        except:
            pass
    return open_ports

if __name__ == "__main__":
    target_host = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port: ").strip())
    end = int(input("Enter end port: ").strip())

    open_ports = port_scan(target_host, start, end)
    os_guess = os_detection(target_host)

    print(f"\n[OS Detection] {os_guess}")
    save_report(target_host, open_ports, os_guess)
