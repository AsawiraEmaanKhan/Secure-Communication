import tkinter as tk
from implementationCode import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, sha256_hash, public_key, private_key
import socket
import threading
from tkinter import scrolledtext


class ServerUI:
    def __init__(self, master):
        self.master = master
        master.title("Server")

        self.label = tk.Label(master, text="Server")
        self.label.pack()

        self.log_label = tk.Label(master, text="Server Logs")
        self.log_label.pack()

        self.log_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=10)
        self.log_area.pack()

        self.msg_label = tk.Label(master, text="Incoming Messages")
        self.msg_label.pack()

        self.msg_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=10)
        self.msg_area.pack()

        self.start_button = tk.Button(master, text="Start Server", command=self.start_server)
        self.start_button.pack()


    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 12345))  # Bind to all available interfaces on port 12345
        self.server_socket.listen(5)  # Listen for up to 5 connections
        self.log_area.insert(tk.END, "Server started...\n")

        # Start a new thread to handle client connections
        threading.Thread(target=self.handle_clients).start()


    def handle_clients(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            self.log_area.insert(tk.END, f"Connection from {client_address}\n")

            # Start a new thread to handle this specific client's messages
            threading.Thread(target=self.handle_client_messages, args=(client_socket,)).start()


    def handle_client_messages(self, client_socket):
        while True:
            encrypted_msg = client_socket.recv(1024)
            if not encrypted_msg:
                break
            # Decrypt the message here and display it
            decrypted_msg = aes_decrypt(encrypted_msg, b'Sixteen byte key')  # Use the appropriate key
            self.msg_area.insert(tk.END, f"Received: {decrypted_msg.decode()}\n")
        client_socket.close()


root = tk.Tk()
server_ui = ServerUI(root)
root.mainloop()
