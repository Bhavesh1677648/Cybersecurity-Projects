import socket
import ssl
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from datetime import datetime
import threading

# ---------- Knowledge bases ----------
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2375: "Docker", 2376: "Docker TLS",
    27017: "MongoDB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

RISKY_PORTS = {
    21: "FTP may allow anonymous login (insecure).",
    22: "SSH exposed – secure with strong credentials.",
    23: "Telnet is insecure (plaintext).",
    25: "SMTP open – check for open relay.",
    53: "DNS server exposed – amplify/poisoning risks.",
    80: "HTTP (unencrypted web traffic).",
    110: "POP3 (plaintext credentials).",
    139: "NetBIOS – may leak host info.",
    143: "IMAP (plaintext variants).",
    445: "SMB – common ransomware target.",
    3306: "MySQL DB open – restrict access.",
    3389: "RDP – high-value brute force target.",
    8080: "HTTP-Alt – often weak admin panels."
}

# ---------- Networking helpers ----------
def detect_protocol(port: int, banner_text: str) -> str:
    # Start with well-known mapping
    proto = COMMON_PORTS.get(port)
    if proto:
        return proto
    # Heuristics from banner
    b = (banner_text or "").lower()
    if "ssh" in b: return "SSH"
    if "ftp" in b: return "FTP"
    if "smtp" in b: return "SMTP"
    if "imap" in b: return "IMAP"
    if "pop3" in b: return "POP3"
    if "http" in b or "server:" in b: return "HTTP"
    if "ssl" in b or "tls" in b: return "TLS Service"
    return "Unknown"

def try_http_banner(sock: socket.socket) -> str:
    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        sock.settimeout(1.5)
        data = sock.recv(2048)
        return data.decode(errors="ignore").strip() or "No banner returned"
    except Exception:
        return "No banner returned"

def grab_banner(target: str, port: int, timeout: float) -> str:
    """
    Attempts a best-effort banner grab.
    Special handling for HTTP (80) and HTTPS (443).
    """
    try:
        if port == 443:
            # HTTPS: wrap with SSL and send HEAD
            raw = socket.create_connection((target, port), timeout=timeout)
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname=target) as tls:
                return try_http_banner(tls)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            if port == 80 or port == 8080 or port == 8000 or port == 8443:
                banner = try_http_banner(s)
            else:
                # Many services speak first; if not, we'll still attempt to read
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    if not banner:
                        # Try a gentle poke for text-based protocols
                        s.sendall(b"\r\n")
                        s.settimeout(1.0)
                        banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = "No banner returned"
            s.close()
            return banner if banner else "No banner returned"
    except Exception:
        return "Banner grab failed"

def scan_single_port(target: str, port: int, timeout: float):
    """
    Returns tuple: (is_open: bool, protocol: str, banner: str, warning: str|None)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            s.close()
            banner = grab_banner(target, port, timeout)
            proto = detect_protocol(port, banner)
            warn = RISKY_PORTS.get(port)
            return True, proto, banner, warn
        else:
            s.close()
            return False, "", "", None
    except Exception:
        return False, "", "", None

# ---------- GUI logic ----------
class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Port Scanner")
        root.geometry("750x600")

        # Top controls
        frm = tk.Frame(root)
        frm.pack(pady=8)

        tk.Label(frm, text="Target Host:").grid(row=0, column=0, sticky="e", padx=4)
        self.entry_target = tk.Entry(frm, width=35)
        self.entry_target.grid(row=0, column=1, padx=4)
        self.entry_target.insert(0, "127.0.0.1")

        tk.Label(frm, text="Start Port:").grid(row=0, column=2, sticky="e", padx=4)
        self.entry_start = tk.Entry(frm, width=8)
        self.entry_start.grid(row=0, column=3, padx=4)
        self.entry_start.insert(0, "1")

        tk.Label(frm, text="End Port:").grid(row=0, column=4, sticky="e", padx=4)
        self.entry_end = tk.Entry(frm, width=8)
        self.entry_end.grid(row=0, column=5, padx=4)
        self.entry_end.insert(0, "1024")

        tk.Label(frm, text="Timeout (s):").grid(row=1, column=0, sticky="e", padx=4, pady=(6,0))
        self.entry_timeout = tk.Entry(frm, width=8)
        self.entry_timeout.grid(row=1, column=1, padx=4, pady=(6,0), sticky="w")
        self.entry_timeout.insert(0, "0.5")

        # Report format
        self.report_format = tk.StringVar(value="txt")
        fmt_frame = tk.Frame(root)
        fmt_frame.pack(pady=4)
        tk.Label(fmt_frame, text="Report Format:").pack(side="left", padx=6)
        ttk.Radiobutton(fmt_frame, text="TXT", value="txt", variable=self.report_format).pack(side="left")
        ttk.Radiobutton(fmt_frame, text="HTML", value="html", variable=self.report_format).pack(side="left")

        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=6)
        self.btn_scan = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.btn_scan.pack(side="left", padx=5)
        self.btn_save = ttk.Button(btn_frame, text="Save Report", command=self.save_report, state="disabled")
        self.btn_save.pack(side="left", padx=5)
        self.btn_clear = ttk.Button(btn_frame, text="Clear", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=5)

        # Progress + status
        self.progress = ttk.Progressbar(root, mode="determinate", length=720)
        self.progress.pack(pady=8)
        self.status_var = tk.StringVar(value="Idle.")
        self.lbl_status = tk.Label(root, textvariable=self.status_var)
        self.lbl_status.pack()

        # Results box
        self.result_box = scrolledtext.ScrolledText(root, width=95, height=22)
        self.result_box.pack(pady=8)

        # Data store for saving report
        self.scan_summary = {
            "target": "",
            "started": None,
            "results": {}  # port -> (protocol, banner, warning)
        }

        self.scanning = False

    def clear_results(self):
        self.result_box.delete(1.0, tk.END)
        self.progress["value"] = 0
        self.status_var.set("Idle.")
        self.scan_summary = {"target": "", "started": None, "results": {}}
        self.btn_save.config(state="disabled")

    def start_scan(self):
        if self.scanning:
            return
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target host/IP.")
            return
        try:
            start = int(self.entry_start.get().strip())
            end = int(self.entry_end.get().strip())
            timeout = float(self.entry_timeout.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers and timeout a number.")
            return
        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Input Error", "Provide a valid port range (1–65535).")
            return
        if timeout <= 0:
            messagebox.showerror("Input Error", "Timeout must be > 0.")
            return

        # Prepare UI
        self.clear_results()
        self.result_box.insert(tk.END, f"Scanning {target} (ports {start}-{end})...\n\n")
        self.result_box.see(tk.END)
        self.progress["maximum"] = end - start + 1
        self.progress["value"] = 0
        self.status_var.set("Starting scan...")
        self.btn_scan.config(state="disabled")
        self.btn_save.config(state="disabled")
        self.scanning = True

        # Prepare data store
        self.scan_summary["target"] = target
        self.scan_summary["started"] = datetime.now()
        self.scan_summary["results"] = {}

        # Launch background thread
        t = threading.Thread(target=self._scan_worker, args=(target, start, end, timeout), daemon=True)
        t.start()

    def _scan_worker(self, target, start, end, timeout):
        total = end - start + 1
        done = 0
        for port in range(start, end + 1):
            is_open, proto, banner, warn = scan_single_port(target, port, timeout)

            # Schedule UI update on the main thread
            def ui_update(p=port, open_=is_open, pr=proto, bn=banner, w=warn):
                # progress
                self.progress["value"] += 1
                pct = (self.progress["value"] / self.progress["maximum"]) * 100
                self.status_var.set(f"Scanning... {int(pct)}%")

                if open_:
                    self.result_box.insert(tk.END, f"[OPEN] Port {p} ({pr}) → {bn}\n")
                    if w:
                        self.result_box.insert(tk.END, f"   ⚠️  {w}\n")
                    self.result_box.see(tk.END)
                    self.scan_summary["results"][p] = (pr, bn, w)

                # At end, finalize
                if self.progress["value"] >= self.progress["maximum"]:
                    self.scanning = False
                    if self.scan_summary["results"]:
                        self.result_box.insert(tk.END, "\nScan complete. Summary:\n")
                        for sp, (spr, sbn, swarn) in sorted(self.scan_summary["results"].items()):
                            self.result_box.insert(tk.END, f"  → Port {sp} ({spr})\n")
                        self.btn_save.config(state="normal")
                    else:
                        self.result_box.insert(tk.END, "\nNo open ports found in the given range.\n")
                        self.btn_save.config(state="normal")
                    self.status_var.set("Done.")
                    self.btn_scan.config(state="normal")

            self.root.after(0, ui_update)

            # Light pacing to keep UI smooth (optional)
            # time.sleep(0.0)

        # Ensure scan end UI enablement even if loop exits unusually
        def ensure_enable():
            if self.scanning:
                self.scanning = False
                self.status_var.set("Done.")
                self.btn_scan.config(state="normal")
                self.btn_save.config(state="normal")
        self.root.after(0, ensure_enable)

    def save_report(self):
        if not self.scan_summary["target"]:
            messagebox.showwarning("No Data", "Run a scan before saving a report.")
            return

        fmt = self.report_format.get()
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        default_name = f"scan_report_{ts}.{fmt}"

        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=default_name,
            filetypes=[("Text", "*.txt"), ("HTML", "*.html"), ("All Files", "*.*")]
        )
        if not path:
            return

        try:
            if fmt == "txt":
                self._save_txt(path)
            else:
                self._save_html(path)
            messagebox.showinfo("Saved", f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _save_txt(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Port Scan Report for {self.scan_summary['target']}\n")
            f.write(f"Generated on: {datetime.now()}\n\n")
            if self.scan_summary["results"]:
                for port, (proto, banner, warn) in sorted(self.scan_summary["results"].items()):
                    f.write(f"[OPEN] Port {port} ({proto}) → {banner}\n")
                    if warn:
                        f.write(f"   ⚠️  {warn}\n")
            else:
                f.write("No open ports found.\n")

    def _save_html(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("<!doctype html><html><head><meta charset='utf-8'>"
                    "<title>Port Scan Report</title>"
                    "<style>"
                    "body{font-family:Arial,Helvetica,sans-serif;margin:20px;}"
                    "h2{margin-bottom:6px}"
                    "table{border-collapse:collapse;width:100%;}"
                    "th,td{border:1px solid #ddd;padding:8px;}"
                    "th{background:#f5f5f5;text-align:left}"
                    ".warn{color:#b00020;font-weight:bold}"
                    "</style></head><body>")
            f.write(f"<h2>Port Scan Report for {self.scan_summary['target']}</h2>")
            f.write(f"<p>Generated on: {datetime.now()}</p><hr>")
            if self.scan_summary["results"]:
                f.write("<table><thead><tr><th>Port</th><th>Protocol</th><th>Banner / Details</th><th>Warning</th></tr></thead><tbody>")
                for port, (proto, banner, warn) in sorted(self.scan_summary["results"].items()):
                    f.write("<tr>")
                    f.write(f"<td>{port}</td>")
                    f.write(f"<td>{proto}</td>")
                    f.write(f"<td>{(banner or '').replace('<','&lt;').replace('>','&gt;')}</td>")
                    f.write(f"<td class='warn'>{warn or ''}</td>")
                    f.write("</tr>")
                f.write("</tbody></table>")
            else:
                f.write("<p>No open ports found.</p>")
            f.write("</body></html>")

# ---------- Run app ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
