from implementationCode import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, sha256_hash, public_key
import socket
import tkinter as tk
from tkinter import scrolledtext



class ClientUI:
    def __init__(self, master):
        self.master = master
        master.title("Client")

        self.label = tk.Label(master, text="Client")
        self.label.pack()

        self.log_label = tk.Label(master, text="Client Logs")
        self.log_label.pack()

        self.log_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=10)
        self.log_area.pack()

        self.msg_label = tk.Label(master, text="Type your message")
        self.msg_label.pack()

        self.msg_entry = tk.Entry(master, width=50)
        self.msg_entry.pack()

        self.send_button = tk.Button(master, text="Send", command=self.send_msg)
        self.send_button.pack()

        self.received_label = tk.Label(master, text="Received Messages")
        self.received_label.pack()

        self.received_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=10)
        self.received_area.pack()

    def send_msg(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 12345))  # Connect to the server on localhost and port 12345

        msg = self.msg_entry.get()
        encrypted_msg = aes_encrypt(msg.encode(), b'Sixteen byte key')  # Use the appropriate key
        client_socket.send(encrypted_msg)

        self.log_area.insert(tk.END, f"Sent: {msg}\n")
        self.msg_entry.delete(0, tk.END)
        client_socket.close()


root = tk.Tk()
client_ui = ClientUI(root)
root.mainloop()
