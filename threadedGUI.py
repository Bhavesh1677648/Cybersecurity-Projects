import socket
import ssl
import csv
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    proto = COMMON_PORTS.get(port)
    if proto:
        return proto
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
    try:
        if port == 443:
            raw = socket.create_connection((target, port), timeout=timeout)
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname=target) as tls:
                return try_http_banner(tls)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            if port in (80, 8080, 8000, 8443):
                banner = try_http_banner(s)
            else:
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    if not banner:
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
    """Returns tuple (port, is_open, protocol, banner, warning)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            banner = grab_banner(target, port, timeout)
            proto = detect_protocol(port, banner)
            warn = RISKY_PORTS.get(port)
            return port, True, proto, banner, warn
        else:
            return port, False, "", "", None
    except Exception:
        return port, False, "", "", None

# ---------- GUI ----------
class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Port Scanner Pro")
        root.geometry("820x640")

        # ---- Top: Inputs ----
        top = ttk.LabelFrame(root, text="Scan Settings")
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(top, text="Target Host/IP").grid(row=0, column=0, padx=6, pady=6, sticky="e")
        self.entry_target = ttk.Entry(top, width=34)
        self.entry_target.grid(row=0, column=1, padx=6, pady=6, sticky="w")
        self.entry_target.insert(0, "127.0.0.1")

        ttk.Label(top, text="Start Port").grid(row=0, column=2, padx=6, pady=6, sticky="e")
        self.entry_start = ttk.Entry(top, width=10)
        self.entry_start.grid(row=0, column=3, padx=6, pady=6, sticky="w")
        self.entry_start.insert(0, "1")

        ttk.Label(top, text="End Port").grid(row=0, column=4, padx=6, pady=6, sticky="e")
        self.entry_end = ttk.Entry(top, width=10)
        self.entry_end.grid(row=0, column=5, padx=6, pady=6, sticky="w")
        self.entry_end.insert(0, "1024")

        ttk.Label(top, text="Timeout (s)").grid(row=1, column=0, padx=6, pady=6, sticky="e")
        self.entry_timeout = ttk.Entry(top, width=10)
        self.entry_timeout.grid(row=1, column=1, padx=6, pady=6, sticky="w")
        self.entry_timeout.insert(0, "0.5")

        ttk.Label(top, text="Threads").grid(row=1, column=2, padx=6, pady=6, sticky="e")
        self.entry_threads = ttk.Entry(top, width=10)
        self.entry_threads.grid(row=1, column=3, padx=6, pady=6, sticky="w")
        self.entry_threads.insert(0, "100")

        fmt_frame = ttk.Frame(top)
        fmt_frame.grid(row=1, column=4, columnspan=2, padx=6, pady=6, sticky="w")
        ttk.Label(fmt_frame, text="Report:").pack(side="left", padx=(0,6))
        self.report_format = tk.StringVar(value="txt")
        ttk.Radiobutton(fmt_frame, text="TXT", value="txt", variable=self.report_format).pack(side="left")
        ttk.Radiobutton(fmt_frame, text="HTML", value="html", variable=self.report_format).pack(side="left")
        ttk.Radiobutton(fmt_frame, text="CSV", value="csv", variable=self.report_format).pack(side="left")

        # ---- Middle: Controls ----
        controls = ttk.Frame(root)
        controls.pack(fill="x", padx=10, pady=(0,8))
        self.btn_scan = ttk.Button(controls, text="Start Scan", command=self.start_scan)
        self.btn_scan.pack(side="left", padx=5)
        self.btn_save = ttk.Button(controls, text="Save Report", command=self.save_report, state="disabled")
        self.btn_save.pack(side="left", padx=5)
        self.btn_clear = ttk.Button(controls, text="Clear Results", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=5)

        # ---- Progress & Status ----
        self.progress = ttk.Progressbar(root, mode="determinate", length=790)
        self.progress.pack(padx=10, pady=6)
        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(root, textvariable=self.status_var).pack(padx=10, anchor="w")

        # ---- Results ----
        box_frame = ttk.LabelFrame(root, text="Results")
        box_frame.pack(fill="both", expand=True, padx=10, pady=8)
        self.result_box = scrolledtext.ScrolledText(box_frame, width=100, height=24)
        self.result_box.pack(fill="both", expand=True, padx=6, pady=6)

        # Data store
        self.scan_summary = {"target": "", "started": None, "results": {}}
        self.scanning = False
        self.lock = threading.Lock()

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
            threads = int(self.entry_threads.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers, timeout a number, threads an integer.")
            return
        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Input Error", "Provide a valid port range (1–65535).")
            return
        if timeout <= 0:
            messagebox.showerror("Input Error", "Timeout must be > 0.")
            return
        if threads < 1 or threads > 1000:
            messagebox.showerror("Input Error", "Threads should be between 1 and 1000.")
            return

        # Reset UI
        self.clear_results()
        self.result_box.insert(tk.END, f"Scanning {target} (ports {start}-{end}) with {threads} threads...\n\n")
        self.progress["maximum"] = end - start + 1
        self.progress["value"] = 0
        self.status_var.set("Starting scan...")
        self.btn_scan.config(state="disabled")
        self.btn_save.config(state="disabled")
        self.scanning = True

        self.scan_summary["target"] = target
        self.scan_summary["started"] = datetime.now()
        self.scan_summary["results"] = {}

        # Launch worker thread (so GUI stays responsive)
        t = threading.Thread(target=self._scan_concurrent, args=(target, start, end, timeout, threads), daemon=True)
        t.start()

    def _scan_concurrent(self, target, start, end, timeout, threads):
        ports = list(range(start, end + 1))
        completed = 0
        total = len(ports)

        def on_done(fut):
            nonlocal completed
            try:
                port, is_open, proto, banner, warn = fut.result()
            except Exception:
                # Just count progress on unexpected errors
                port, is_open, proto, banner, warn = (None, False, "", "", None)

            def ui_update():
                # progress
                self.progress["value"] += 1
                pct = int((self.progress["value"] / self.progress["maximum"]) * 100)
                self.status_var.set(f"Scanning... {pct}%")

                if is_open and port is not None:
                    self.result_box.insert(tk.END, f"[OPEN] Port {port} ({proto}) → {banner}\n")
                    if warn:
                        self.result_box.insert(tk.END, f"   ⚠️  {warn}\n")
                    self.result_box.see(tk.END)
                    with self.lock:
                        self.scan_summary["results"][port] = (proto, banner, warn)

                # finalize
                if self.progress["value"] >= self.progress["maximum"]:
                    self.scanning = False
                    if self.scan_summary["results"]:
                        self.result_box.insert(tk.END, "\nScan complete. Summary:\n")
                        for sp in sorted(self.scan_summary["results"]):
                            pr, _, _ = self.scan_summary["results"][sp]
                            self.result_box.insert(tk.END, f"  → Port {sp} ({pr})\n")
                    else:
                        self.result_box.insert(tk.END, "\nNo open ports found in the given range.\n")
                    self.status_var.set("Done.")
                    self.btn_scan.config(state="normal")
                    self.btn_save.config(state="normal")

            self.root.after(0, ui_update)

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = [ex.submit(scan_single_port, target, p, timeout) for p in ports]
                for fut in futures:
                    fut.add_done_callback(lambda f: on_done(f))
                # Block until all work finished (without freezing GUI updates because updates are via after())
                for _ in as_completed(futures):
                    pass
        except Exception as e:
            def ui_err():
                messagebox.showerror("Scan Error", str(e))
                self.status_var.set("Error.")
                self.btn_scan.config(state="normal")
            self.root.after(0, ui_err)

    def save_report(self):
        if not self.scan_summary["results"]:
            messagebox.showwarning("No Data", "Run a scan before saving a report.")
            return

        fmt = self.report_format.get()
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        default_name = f"scan_report_{ts}.{fmt}"
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=default_name,
            filetypes=[("Text", "*.txt"), ("HTML", "*.html"), ("CSV", "*.csv"), ("All Files", "*.*")]
        )
        if not path:
            return

        try:
            if fmt == "txt":
                self._save_txt(path)
            elif fmt == "html":
                self._save_html(path)
            else:
                self._save_csv(path)
            messagebox.showinfo("Saved", f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _save_txt(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Port Scan Report for {self.scan_summary['target']}\n")
            f.write(f"Generated on: {datetime.now()}\n\n")
            for port, (proto, banner, warn) in sorted(self.scan_summary["results"].items()):
                f.write(f"[OPEN] Port {port} ({proto}) → {banner}\n")
                if warn:
                    f.write(f"   ⚠️  {warn}\n")

    def _save_html(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("<!doctype html><html><head><meta charset='utf-8'>"
                    "<title>Port Scan Report</title>"
                    "<style>"
                    "body{font-family:Arial,Helvetica,sans-serif;margin:20px;}"
                    "h2{margin-bottom:6px}"
                    "table{border-collapse:collapse;width:100%;}"
                    "th,td{border:1px solid #ddd;padding:8px;vertical-align:top}"
                    "th{background:#f5f5f5;text-align:left}"
                    ".warn{color:#b00020;font-weight:bold}"
                    "</style></head><body>")
            f.write(f"<h2>Port Scan Report for {self.scan_summary['target']}</h2>")
            f.write(f"<p>Generated on: {datetime.now()}</p><hr>")
            f.write("<table><thead><tr><th>Port</th><th>Protocol</th><th>Banner / Details</th><th>Warning</th></tr></thead><tbody>")
            for port, (proto, banner, warn) in sorted(self.scan_summary["results"].items()):
                safe_banner = (banner or "").replace("<", "&lt;").replace(">", "&gt;")
                f.write(f"<tr><td>{port}</td><td>{proto}</td><td>{safe_banner}</td><td class='warn'>{warn or ''}</td></tr>")
            f.write("</tbody></table></body></html>")

    def _save_csv(self, path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", self.scan_summary["target"]])
            writer.writerow(["Generated on", str(datetime.now())])
            writer.writerow([])
            writer.writerow(["Port", "Protocol", "Banner/Details", "Warning"])
            for port, (proto, banner, warn) in sorted(self.scan_summary["results"].items()):
                writer.writerow([port, proto, banner, warn or ""])

# ---------- Run app ----------
if __name__ == "__main__":
    root = tk.Tk()
    # Make ttk look a bit nicer
    try:
        root.call("source", "sun-valley.tcl")  # if present
        ttk.Style().theme_use("sun-valley-dark")
    except Exception:
        pass
    app = ScannerGUI(root)
    root.mainloop()
