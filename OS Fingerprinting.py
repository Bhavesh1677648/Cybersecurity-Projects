import socket
import struct
import time
import os

def detect_os(target):
    try:
        # Create raw socket for ICMP
        icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp.settimeout(2)

        # Build ICMP Echo Request (ping)
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = os.getpid() & 0xFFFF
        icmp_seq = 1
        payload = b'GPTScannerTest'

        header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        checksum = calculate_checksum(header + payload)
        header = struct.pack("bbHHh", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        packet = header + payload

        # Send ICMP packet
        icmp.sendto(packet, (target, 1))

        # Receive response
        start_time = time.time()
        reply, addr = icmp.recvfrom(1024)
        rtt = (time.time() - start_time) * 1000

        # Extract TTL from IP header
        ip_header = reply[:20]
        ttl = ip_header[8]

        os_guess = guess_os(ttl)

        print(f"\n[+] ICMP Reply from {addr[0]} in {rtt:.2f} ms")
        print(f"[+] TTL Value: {ttl} → Likely OS: {os_guess}")
        return os_guess

    except PermissionError:
        print("\n[!] You need to run this script as Administrator/root to use raw sockets!")
    except socket.timeout:
        print("\n[!] No ICMP reply received. Target may be blocking ping.")
    except Exception as e:
        print(f"\n[!] Error during OS detection: {e}")


def calculate_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff


def guess_os(ttl):
    if ttl >= 128:
        return "Windows (typical TTL=128)"
    elif ttl >= 64:
        return "Linux/Unix/macOS (typical TTL=64)"
    elif ttl >= 255:
        return "Network Device/Router (typical TTL=255)"
    else:
        return "Unknown OS"


# =====================
# Run (Standalone Test)
# =====================
if __name__ == "__main__":
    target = input("Enter target host (IP or domain): ").strip()
    detect_os(target)
