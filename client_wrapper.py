import socket
import tkinter as tk
from tkinter import messagebox
from vpn_client import VPN_CLIENT

### Server details (remote machine) ###

CLIENT = VPN_CLIENT()

if __name__ == "__main__":
    # GUI setup using tkinter
    root = tk.Tk()
    root.title("CPEN 442 Assignment 6: VPN Client")
    tk.Label(root, text="Enter your message:").pack(pady=10)

    message_entry = tk.Text(root, width=50, height=5)
    result_label = tk.Label(root, text="Status")
    send_button = tk.Button(root, text="Send", command=lambda: CLIENT.send_message(message_entry.get("1.0", 'end'), result_label))
    
    message_entry.pack(pady=5)
    send_button.pack(pady=10)
    result_label.pack(pady=10)

    root.mainloop()
