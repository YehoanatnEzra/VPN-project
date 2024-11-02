import socket, sys
import logging
import tkinter as tk
from keys import CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY
from crypto import parse_key
import os

HOST = "127.0.0.1"  # Replace with the remote server's IP address. Do not change unless testing on two different devices.
# You can run server_wrapper.py on another terminal on the same device for development purposes.
PORT = 65432  # Port the server is listening on


class VPN_CLIENT:
    def __init__(self):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.s_pub = (
            None  # Server public key, set only when the connection is established
        )
        self.c_priv = parse_key(CLIENT_PRIVATE_KEY)  # Client private/public keypair
        self.nonce = 0

        self.debug_enabled = "DEBUG" in os.environ

        self.__debug("Debug mode enabled.")

    def __debug(self, *args):
        if self.debug_enabled:
            print("DEBUG:", *args)

    def needs_key_exchange(self):
        return self.s_pub is None

    def establish_connection(self) -> bool:
        # We assume here that integrity/authentication is not compromised by Mallory
        # However, she's listening

        encoded_s_pub = self.broadcast(CLIENT_PUBLIC_KEY)
        self.s_pub = parse_key(encoded_s_pub)

        return True

    def encrypt(self, message: str) -> str:
        # TODO: call and return serialize_payload(...) with the right params
        return message

    def send_message(self, message: str, output: tk.Label) -> None:
        """Sends a message and gives the output to a tkinter label"""
        output.config(text="Encrypting message")

        if self.needs_key_exchange():
            output.config(text="Exchanging initial keys with the server...")
            self.__debug("Exchanging keys...")
            self.establish_connection()

        output.config(text="Sending message...")
        message = self.encrypt(message)
        # TODO: add a reasonable timeout and reattempt sending a message if the timeout is exceeded
        ack = self.broadcast(message)

        # TODO: use the key contained in the ack to update the ratchet
        # ensure this message has a unique nonce /  wasn't replayed
        # ensure correctly formatted json, validate the hmac with validate_payload_hmac
        # parse the ack with parse_payload(...) to get the nonce, key, etc
        # can do something with the ciphertext if need be

        # Write output to interface label
        output.config(text="Message sent!")

    # Do not modify this function
    def broadcast(self, payload: str) -> str:
        """Broadcasts a payload through a socket, return replies from server"""
        if not payload.strip() or sys.getsizeof(payload) > 1024:
            raise RuntimeError("Bad payload")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # TODO: remove this line before we submit since it says we shouldnt modify this func
                self.__debug("Client sending:", payload)
                s.connect((HOST, PORT))
                s.sendall(payload.encode("utf-8"))

                # Wait for acknowledgment from the server
                data = s.recv(1024)
                return data.decode("utf-8")
        except Exception as e:
            return f"Error: {e}"
