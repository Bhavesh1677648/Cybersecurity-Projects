import socket
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import datetime
import threading

def scan_ports():
    target = entry_target.get()
    try:
        start = int(entry_start.get())
        end = int(entry_end.get())
    except ValueError:
        messagebox.showerror("Input Error", "Port numbers must be integers!")
        return

    if not target:
        messagebox.showerror("Input Error", "Please enter a target host!")
        return

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, f"Scanning {target} ({start}-{end})...\n\n")

    open_ports = []
    total_ports = end - start + 1
    progress_bar["maximum"] = total_ports
    progress_bar["value"] = 0

    for i, port in enumerate(range(start, end + 1), start=1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                result_box.insert(tk.END, f"[OPEN] Port {port}\n")
                result_box.see(tk.END)
                open_ports.append(port)
            s.close()
        except Exception:
            pass

        # Update progress bar
        progress_bar["value"] = i
        root.update_idletasks()

    if not open_ports:
        result_box.insert(tk.END, "\nNo open ports found.\n")
    else:
        result_box.insert(tk.END, f"\nScan complete. Open ports: {open_ports}\n")

def start_scan():
    threading.Thread(target=scan_ports, daemon=True).start()

def save_report():
    content = result_box.get(1.0, tk.END).strip()
    if not content:
        messagebox.showwarning("Warning", "No scan results to save!")
        return

    file = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file:
        with open(file, "w", encoding="utf-8") as f:
            f.write("Port Scan Report\n")
            f.write(f"Generated on: {datetime.datetime.now()}\n\n")
            f.write(content)
        messagebox.showinfo("Saved", f"Report saved as {file}")

# --- GUI Layout ---
root = tk.Tk()
root.title("Port Scanner")
root.geometry("600x450")

# Input fields
tk.Label(root, text="Target Host:").pack()
entry_target = tk.Entry(root, width=40)
entry_target.pack()

tk.Label(root, text="Start Port:").pack()
entry_start = tk.Entry(root, width=10)
entry_start.pack()

tk.Label(root, text="End Port:").pack()
entry_end = tk.Entry(root, width=10)
entry_end.pack()

# Buttons
tk.Button(root, text="Start Scan", command=start_scan).pack(pady=5)
tk.Button(root, text="Save Report", command=save_report).pack(pady=5)

# Progress bar
progress_bar = ttk.Progressbar(root, length=500, mode="determinate")
progress_bar.pack(pady=10)

# Results box
result_box = scrolledtext.ScrolledText(root, width=70, height=15)
result_box.pack(pady=10)

root.mainloop()
