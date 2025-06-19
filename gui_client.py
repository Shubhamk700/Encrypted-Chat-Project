import socket
import threading
import tkinter as tk
from tkinter import simpledialog
from aes_cipher import AESCipher

HOST = '127.0.0.1'
PORT = 5555
KEY = b'mysecretaeskey12'

cipher = AESCipher(KEY)


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")

        # Header
        header = tk.Label(root, text="Encrypted Chat", bg="#075E54", fg="white", font=("Helvetica", 16), pady=10)
        header.pack(fill=tk.X)

        # Chat area with scrollable canvas
        self.chat_frame = tk.Frame(root, bg="#ECE5DD")
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(self.chat_frame, bg="#ECE5DD", highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.chat_frame, orient="vertical", command=self.canvas.yview)
        self.bubble_frame = tk.Frame(self.canvas, bg="#ECE5DD")

        self.bubble_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.bubble_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Message input area
        self.bottom_frame = tk.Frame(root, bg="white")
        self.bottom_frame.pack(fill=tk.X)

        self.entry = tk.Entry(self.bottom_frame, font=("Helvetica", 12))
        self.entry.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(self.bottom_frame, text="Send", command=self.send_message, bg="#25D366", fg="white")
        self.send_btn.pack(side=tk.RIGHT, padx=10)

        # Username
        self.username = simpledialog.askstring("Username", "Enter your name:", parent=root)
        if not self.username:
            self.username = "Anonymous"

        # Connect
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            self.client_socket.send(cipher.encrypt(self.username))
        except Exception as e:
            self.display_message(f"Connection error: {e}", is_self=False)
            return

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if msg:
            full_msg = f"{self.username}: {msg}"
            encrypted = cipher.encrypt(full_msg)
            try:
                self.client_socket.send(encrypted)
                self.display_message(full_msg, is_self=True)  # Manually display it
                self.entry.delete(0, tk.END)
            except:
                self.display_message("❌ Failed to send message.", is_self=False)

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024)
                message = cipher.decrypt(data)
                if not message.startswith(f"{self.username}:"):  # avoid displaying own message again
                    self.display_message(message, is_self=False)
            except:
                self.display_message("⚠️ Disconnected.", is_self=False)
                break

    def display_message(self, message, is_self=None):
        if is_self is None:
            is_self = message.startswith(f"{self.username}:")

        # Message container
        msg_frame = tk.Frame(self.bubble_frame, bg="#ECE5DD")
        msg_frame.pack(anchor="e" if is_self else "w", padx=10, pady=3, fill="x")

        # Colors and appearance
        bubble_color = "#DCF8C6" if is_self else "white"

        if is_self:
            # Store original and masked version
            original_text = message
            masked_text = "•" * len(message)

            text_var = tk.StringVar(value=masked_text)

            bubble = tk.Label(
                msg_frame,
                textvariable=text_var,
                bg=bubble_color,
                fg="black",
                wraplength=400,
                justify="left",
                font=("Helvetica", 12),
                padx=10,
                pady=5,
                bd=0,
                relief="solid"
            )
            bubble.pack(side=tk.LEFT, padx=(5, 2))

            def toggle():
                current = text_var.get()
                text_var.set(original_text if current == masked_text else masked_text)

            toggle_btn = tk.Button(msg_frame, text="👁️", width=2, command=toggle, bg="#DCF8C6", bd=0)
            toggle_btn.pack(side=tk.RIGHT, padx=(2, 5))

        else:
            bubble = tk.Label(
                msg_frame,
                text=message,
                bg=bubble_color,
                fg="black",
                wraplength=400,
                justify="left",
                font=("Helvetica", 12),
                padx=10,
                pady=5,
                bd=0,
                relief="solid"
            )
            bubble.pack(anchor="w", padx=5)

        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)


if __name__ == "__main__":
    root = tk.Tk()
    ChatClient(root)
    root.mainloop()
