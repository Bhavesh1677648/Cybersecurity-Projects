import socket

def port_scan(target, start_port, end_port):
    print(f"\n[+] Scanning target: {target}")
    print(f"[+] Port range: {start_port}-{end_port}\n")

    for port in range(start_port, end_port + 1):
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # short timeout for faster scanning

            # Try to connect
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port}")
            else:
                print(f"[CLOSED] Port {port}")

            s.close()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            break
        except socket.gaierror:
            print("[!] Hostname could not be resolved.")
            break
        except socket.error:
            print("[!] Could not connect to server.")
            break

if __name__ == "__main__":
    target_host = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))

    port_scan(target_host, start, end)
