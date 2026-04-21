import tkinter as tk
import threading
import nmap

def start_scan(event=None):
    button.config(state="disabled")
    status_label.config(text="Scanning...")
    text_box.delete("1.0", tk.END)
    text_box.config(state='disabled')

    threading.Thread(target=run_scan, daemon=True).start()

def run_scan():
    target = entry.get()

    try:
        nm = nmap.PortScanner()
        nm.scan(target, '22-443')

        output = ""

        for host in nm.all_hosts():
            output += f"\nHost: {host} ({nm[host].hostname()})\n"
            output += f"State: {nm[host].state()}\n"

            for proto in nm[host].all_protocols():
                ports = sorted(nm[host][proto].keys())

                for port in ports:
                    state = nm[host][proto][port]['state']
                    
                    # ONLY SHOW OPEN PORTS (high signal)
                    if state == "open":
                        output += f"[OPEN] Port {port} ({proto})\n"

        if output == "":
            output = "No open ports found."

        # Update UI safely
        root.after(0, update_ui, output)

    except Exception as e:
        root.after(0, update_ui, f"Error: {str(e)}")

def update_ui(output):
    text_box.config(state="normal")        # enable temporarily
    text_box.insert(tk.END, output)
    text_box.config(state="disabled")      # disable again

    status_label.config(text="Scan Complete")
    button.config(state="normal")
# UI SETUP
root = tk.Tk()
root.title("Network Scanner - Zenith0x01")
root.geometry("520x420")

label = tk.Label(root, text="Enter domain/IP Address:")
label.pack()

entry = tk.Entry(root, width=40)
entry.pack()

entry.bind('<Return>', start_scan)

button = tk.Button(root, text="Scan Network", command=start_scan)
button.pack()

status_label = tk.Label(root, text="Idle")
status_label.pack()

text_box = tk.Text(root, height=18, width=65,state='disabled')
text_box.pack()

root.mainloop()