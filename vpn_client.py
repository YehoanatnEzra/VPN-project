import socket, sys
import logging
import tkinter as tk
from keys import CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY

HOST = '127.0.0.1'      # Replace with the remote server's IP address. Do not change unless testing on two different devices.
                        # You can run server_wrapper.py on another terminal on the same device for development purposes.
PORT = 65432            # Port the server is listening on

class VPN_CLIENT:
    def __init__(self):
        # TODO Your code here
        # maybe store some keys here
        pass

    def establish_connection(self) -> bool:
        # TODO Your code here
        return True
    
    def encrypt(self, message: str) -> str:
        # TODO Your code here
        return message

    def send_message(self, message: str, output: tk.Label) -> None:
        """Sends a message and gives the output to a tkinter label"""
        output.config(text="Encrypting message")

        # TODO Your code here 
        # any setup things to do?

        self.establish_connection()
        message = self.encrypt(message)
        self.broadcast(message)

        # Write output to interface label
        output.config(text="Message sent!")

    # Do not modify this function
    def broadcast(self, payload: str) -> str:
        """Broadcasts a payload through a socket, return replies from server"""
        if not payload.strip() or sys.getsizeof(payload) > 1024:
            raise RuntimeError("Bad payload")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(payload.encode('utf-8'))

                # Wait for acknowledgment from the server
                data = s.recv(1024)
                return data.decode('utf-8')
        except Exception as e:
            return f"Error: {e}"