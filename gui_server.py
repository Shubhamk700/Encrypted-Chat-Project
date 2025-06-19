import socket
import threading
import tkinter as tk
from aes_cipher import AESCipher

HOST = '127.0.0.1'
PORT = 5555
KEY = b'mysecretaeskey12'

cipher = AESCipher(KEY)
clients = []
username_map = {}

class ChatServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Server")
        self.root.geometry("750x550")

        # Chat frame with scrollable canvas
        self.chat_frame = tk.Frame(root, bg="#ECE5DD")
        self.chat_frame.grid(row=0, column=0, rowspan=3, padx=10, pady=10, sticky="nsew")

        self.canvas = tk.Canvas(self.chat_frame, bg="#ECE5DD", highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.chat_frame, orient="vertical", command=self.canvas.yview)
        self.bubble_frame = tk.Frame(self.canvas, bg="#ECE5DD")

        self.bubble_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.bubble_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Connected clients
        self.client_label = tk.Label(root, text="Connected Clients")
        self.client_label.grid(row=0, column=1)

        self.client_listbox = tk.Listbox(root, width=30, height=20)
        self.client_listbox.grid(row=1, column=1, sticky="n")

        # Server input area
        self.message_entry = tk.Entry(root, font=("Helvetica", 12))
        self.message_entry.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        self.message_entry.bind("<Return>", self.send_server_message)

        self.send_button = tk.Button(root, text="Send", command=self.send_server_message, bg="#075E54", fg="white")
        self.send_button.grid(row=2, column=1, sticky="ew", padx=10)

        # Status
        self.status = tk.Label(root, text="Starting server...", fg="blue")
        self.status.grid(row=3, column=0, columnspan=2)

        self.start_server()

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, PORT))
        self.server.listen()
        self.status.config(text=f"Server running on {HOST}:{PORT}", fg="green")
        threading.Thread(target=self.accept_clients, daemon=True).start()

    def accept_clients(self):
        while True:
            conn, addr = self.server.accept()
            try:
                username_encrypted = conn.recv(1024)
                username = cipher.decrypt(username_encrypted)
            except:
                conn.close()
                continue
            clients.append(conn)
            username_map[conn] = username
            self.update_client_listbox()
            self.display_message(f"[+] {username} connected.", "system")
            threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def handle_client(self, conn):
        username = username_map.get(conn, "Unknown")
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                message = cipher.decrypt(data)
                self.display_message(message)
                self.broadcast(cipher.encrypt(message), conn)
            except:
                break
        self.display_message(f"[!] {username} disconnected.", "system")
        if conn in clients:
            clients.remove(conn)
        if conn in username_map:
            del username_map[conn]
        self.update_client_listbox()
        conn.close()

    def send_server_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            full_msg = f"[Server]: {message}"
            encrypted = cipher.encrypt(full_msg)
            self.broadcast(encrypted, None)
            self.display_message(full_msg, "server")
            self.message_entry.delete(0, tk.END)

    def broadcast(self, message, sender_conn):
        for client in clients:
            if client != sender_conn:
                try:
                    client.send(message)
                except:
                    client.close()
                    if client in clients:
                        clients.remove(client)
                    if client in username_map:
                        del username_map[client]
                    self.update_client_listbox()

    def update_client_listbox(self):
        self.client_listbox.delete(0, tk.END)
        for name in username_map.values():
            self.client_listbox.insert(tk.END, name)

    def display_message(self, message, sender="client"):
        msg_frame = tk.Frame(self.bubble_frame, bg="#ECE5DD")
        anchor = "w" if sender == "client" else "e" if sender == "server" else "center"
        msg_frame.pack(anchor=anchor, padx=10, pady=3, fill="x")

        bubble_color = "#DCF8C6" if sender == "server" else "white" if sender == "client" else "#F0F0F0"

        bubble = tk.Label(
            msg_frame,
            text=message,
            bg=bubble_color,
            fg="black",
            wraplength=450,
            justify="left",
            font=("Helvetica", 12),
            padx=10,
            pady=5,
            bd=0,
            relief="solid"
        )
        bubble.pack(anchor=anchor, padx=5)

        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

if __name__ == "__main__":
    root = tk.Tk()
    ChatServerGUI(root)
    root.mainloop()
