import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import threading
import string
import time
from datetime import datetime

from wifi_utils import get_card, scan_wifi, detect_encryption
from bruteforce import (
    crack_wifi_bruteforce, crack_wifi_wordlist,
    set_stop_flag, reset_stop_flag
)

class WifiCrackApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WiFi Brute-force Cracker Pro")
        self.geometry("800x650")
        self.card = get_card()
        if not self.card:
            messagebox.showerror("Error", "No wifi card found or unable to disconnect.")
            self.destroy()
            return
        self.wifi_list = []
        self.wordlist = None
        self.max_attempts = None
        self.create_widgets()
        self.crack_thread = None

    def create_widgets(self):
        # WiFi Scan Section
        scan_frame = tk.LabelFrame(self, text="WiFi Scan", padx=10, pady=10)
        scan_frame.pack(fill="x", padx=10, pady=5)

        self.scan_btn = tk.Button(scan_frame, text="Scan WiFi", command=self.scan_and_show)
        self.scan_btn.pack(side=tk.LEFT)

        self.refresh_label = tk.Label(scan_frame, text="Scan result:")
        self.refresh_label.pack(side=tk.LEFT, padx=10)

        # WiFi List Section
        list_frame = tk.LabelFrame(self, text="Available WiFi Networks", padx=10, pady=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        listbox_frame = tk.Frame(list_frame)
        listbox_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(listbox_frame, columns=("SSID", "BSSID", "Signal", "Encryption"), show="headings", height=10)
        self.tree.heading("SSID", text="SSID")
        self.tree.heading("BSSID", text="BSSID")
        self.tree.heading("Signal", text="Signal")
        self.tree.heading("Encryption", text="Encryption")
        self.tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Attack Settings Section
        crack_frame = tk.LabelFrame(self, text="Attack Settings", padx=10, pady=10)
        crack_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(crack_frame, text="Charset:").pack(side=tk.LEFT)
        self.charset_var = tk.StringVar(value="printable")
        tk.Radiobutton(crack_frame, text="Printable", variable=self.charset_var, value="printable").pack(side=tk.LEFT)
        tk.Radiobutton(crack_frame, text="Lowercase", variable=self.charset_var, value="lowercase").pack(side=tk.LEFT)
        tk.Radiobutton(crack_frame, text="Numbers", variable=self.charset_var, value="digits").pack(side=tk.LEFT)
        tk.Radiobutton(crack_frame, text="Custom", variable=self.charset_var, value="custom").pack(side=tk.LEFT)
        self.custom_charset_entry = tk.Entry(crack_frame, width=15)
        self.custom_charset_entry.pack(side=tk.LEFT)
        self.custom_charset_entry.insert(0, "")

        tk.Label(crack_frame, text="Max Attempts (optional):").pack(side=tk.LEFT, padx=10)
        self.max_attempts_entry = tk.Entry(crack_frame, width=8)
        self.max_attempts_entry.pack(side=tk.LEFT)

        # Wordlist Section
        wordlist_frame = tk.LabelFrame(self, text="Dictionary Attack", padx=10, pady=10)
        wordlist_frame.pack(fill="x", padx=10, pady=5)
        self.wordlist_label = tk.Label(wordlist_frame, text="No wordlist loaded.")
        self.wordlist_label.pack(side=tk.LEFT)
        self.load_wordlist_btn = tk.Button(wordlist_frame, text="Load Wordlist", command=self.load_wordlist)
        self.load_wordlist_btn.pack(side=tk.LEFT, padx=10)

        # Control Buttons Section
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=5)
        self.start_crack_btn = tk.Button(btn_frame, text="Start Cracking", command=self.start_cracking_thread)
        self.start_crack_btn.pack(side=tk.LEFT, padx=5)
        self.stop_crack_btn = tk.Button(btn_frame, text="Stop", command=self.stop_cracking)
        self.stop_crack_btn.pack(side=tk.LEFT, padx=5)
        self.reset_btn = tk.Button(btn_frame, text="Reset", command=self.reset_ui)
        self.reset_btn.pack(side=tk.LEFT, padx=5)

        # Status Section
        status_frame = tk.LabelFrame(self, text="Status", padx=10, pady=10)
        status_frame.pack(fill="x", padx=10, pady=5)
        self.result_label = tk.Label(status_frame, text="", fg="blue")
        self.result_label.pack(anchor="w")
        self.status_label = tk.Label(status_frame, text="Status: Idle", fg="green")
        self.status_label.pack(anchor="w")
        self.counter_label = tk.Label(status_frame, text="Attempts: 0", fg="purple")
        self.counter_label.pack(anchor="w")

    def scan_and_show(self):
        self.status_label.config(text="Status: Scanning...")
        self.update_idletasks()
        self.tree.delete(*self.tree.get_children())
        self.wifi_list = scan_wifi(self.card)
        for idx, wifi in enumerate(self.wifi_list):
            ssid = wifi.ssid
            bssid = getattr(wifi, "bssid", "N/A")
            signal = getattr(wifi, "signal", "N/A")
            encryption = detect_encryption(wifi)
            self.tree.insert("", "end", iid=idx, values=(ssid, bssid, signal, encryption))
        self.status_label.config(text="Status: Scan complete.")

    def get_charset(self):
        mode = self.charset_var.get()
        if mode == "printable":
            return string.printable.strip()
        elif mode == "lowercase":
            return string.ascii_lowercase
        elif mode == "digits":
            return string.digits
        elif mode == "custom":
            val = self.custom_charset_entry.get()
            return val if val else string.printable.strip()
        else:
            return string.printable.strip()

    def load_wordlist(self):
        file_path = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
                self.wordlist_label.config(text=f"Loaded: {file_path} ({len(self.wordlist)} words)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load wordlist: {e}")
                self.wordlist = None
                self.wordlist_label.config(text="No wordlist loaded.")

    def start_cracking_thread(self):
        reset_stop_flag()
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a WiFi network.")
            return
        idx = int(selection[0])
        wifi_info = self.wifi_list[idx]
        ssid = wifi_info.ssid
        encryption = detect_encryption(wifi_info)
        self.result_label.config(text=f"Cracking SSID: {ssid} ({encryption}) ...")
        self.status_label.config(text="Status: Cracking in progress...")
        self.counter_label.config(text="Attempts: 0")
        charset = self.get_charset()
        max_attempts = self.max_attempts_entry.get()
        self.max_attempts = int(max_attempts) if max_attempts.isdigit() else None
        self.start_crack_btn.config(state=tk.DISABLED)
        self.stop_crack_btn.config(state=tk.NORMAL)
        self.reset_btn.config(state=tk.DISABLED)
        if self.wordlist:
            thread = threading.Thread(target=self.crack_wifi_wordlist_with_status, args=(ssid, encryption))
        else:
            thread = threading.Thread(target=self.crack_wifi_with_status, args=(ssid, encryption, charset))
        thread.daemon = True
        self.crack_thread = thread
        thread.start()

    def crack_wifi_with_status(self, ssid, encryption, charset):
        def update_status(pwd, attempt, max_attempts):
            percent = ""
            if max_attempts:
                percent = f" ({attempt}/{max_attempts}, {attempt*100//max_attempts}%)"
            self.status_label.config(text=f"Trying password: {pwd}{percent}")
            self.counter_label.config(text=f"Attempts: {attempt}")
            self.update_idletasks()
        result, attempts = crack_wifi_bruteforce(
            ssid, self.card, update_status_callback=update_status,
            charset=charset, encryption=encryption, max_attempts=self.max_attempts
        )
        self.finish_crack(ssid, result, attempts)

    def crack_wifi_wordlist_with_status(self, ssid, encryption):
        def update_status(pwd, attempt, total):
            percent = ""
            if total:
                percent = f" ({attempt}/{total}, {attempt*100//total}%)"
            self.status_label.config(text=f"Trying password: {pwd}{percent}")
            self.counter_label.config(text=f"Attempts: {attempt}")
            self.update_idletasks()
        result, attempts = crack_wifi_wordlist(
            ssid, self.card, self.wordlist, update_status_callback=update_status, encryption=encryption
        )
        self.finish_crack(ssid, result, attempts)

    def finish_crack(self, ssid, result, attempts):
        self.start_crack_btn.config(state=tk.NORMAL)
        self.stop_crack_btn.config(state=tk.DISABLED)
        self.reset_btn.config(state=tk.NORMAL)
        if result:
            self.result_label.config(text=f"Password for {ssid}: {result}")
            self.status_label.config(text="Status: Success!")
            self.save_cracked_result(ssid, result)
        else:
            self.result_label.config(text="Failed to crack the WiFi password or stopped.")
            self.status_label.config(text="Status: Finished.")
        self.counter_label.config(text=f"Attempts: {attempts}")

    def stop_cracking(self):
        set_stop_flag(True)
        self.status_label.config(text="Status: Stopping...")
        self.start_crack_btn.config(state=tk.NORMAL)
        self.stop_crack_btn.config(state=tk.DISABLED)
        self.reset_btn.config(state=tk.NORMAL)

    def reset_ui(self):
        self.result_label.config(text="")
        self.status_label.config(text="Status: Idle")
        self.counter_label.config(text="Attempts: 0")
        self.wordlist = None
        self.wordlist_label.config(text="No wordlist loaded.")
        self.max_attempts_entry.delete(0, tk.END)
        self.start_crack_btn.config(state=tk.NORMAL)
        self.stop_crack_btn.config(state=tk.NORMAL)
        self.reset_btn.config(state=tk.NORMAL)

    def save_cracked_result(self, ssid, pwd):
        try:
            with open("cracked_results.txt", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} | SSID: {ssid} | Password: {pwd}\n")
        except Exception as e:
            print(f"Error saving cracked result: {e}")

if __name__ == "__main__":
    app = WifiCrackApp()
    app.mainloop()