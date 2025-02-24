import socket, sys
import tkinter as tk
from keys import CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY
from crypto import *
from message import Message

HOST = "127.0.0.1"  # Replace with the remote server's IP address. Do not change unless testing on two different
# devices.
# You can run server_wrapper.py on another terminal on the same device for development purposes.
PORT = 65431  # Port the server is listening on
MAX_RETRIES = 1000


class VPN_CLIENT:
    def __init__(self):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.s_pub = None  # Server public key, set only when the connection is established
        self.c_priv = parse_key(CLIENT_PRIVATE_KEY)  # Client private/public keypair
        self.secret = None
        self.nonce = 0
        self.detected_integrity_error = False
        self.detected_general_error = False
        self.sent_integrity_warning = False
        self.sent_general_warning = False

    def send_message(self, message: str, output: tk.Label) -> None:
        """Sends a message and gives the output to a tkinter label"""
        self.assert_connection()
        self.update_keys()
        msg = Message(self.nonce, message, self.secret, self.c_priv)
        self.update_warnings(msg)  # A call to this function might be for sending a warning
        output.config(text="Encrypting message")
        message_to_send = msg.prepare_for_sending()
        output.config(text="Sending message...")
        ack = self.broadcast(message_to_send)
        try:
            self.handle_ack(ack, output)
        except Exception as e:
            self.update_warnings(msg, e)
            self.resend(msg, output)

    def handle_ack(self, server_m: str, output: tk.Label) -> None:
        server_nonce = self.nonce + 1
        ack_dict = Message.deserialize_payload(server_m)
        print(ack_dict)
        new_s_pub = Message.get_new_pub_key(ack_dict)
        secret = generate_shared_secret(self.c_priv, parse_key(new_s_pub))
        msg = Message.verify_and_parse(ack_dict, secret, server_nonce)
        plaintext = msg.msg_decrypt(derive_enc_key(secret))
        self.s_pub = parse_key(new_s_pub)
        self.nonce = server_nonce + 1
        output.config(text="Message sent!")

    def resend(self, msg: Message, output: tk.Label) -> None:
        """Resends msg after first attempt failed, this time with an availability warning. Tries MAX_RETRIES times."""
        # This function is crucial - we can't use send_message, because we must keep the original ciphertext
        for _ in range(MAX_RETRIES):
            msg.nonce += 2
            self.nonce += 2
            message_to_send = msg.prepare_for_sending()  # Does not re-encrypt
            try:
                ack = self.broadcast(message_to_send)
                self.handle_ack(ack, output)
                return
            except Exception as e:
                self.update_warnings(msg, e=e)
        raise Exception(f"Probably no connection. {MAX_RETRIES} retries with no response.")

    def assert_connection(self):
        if self.needs_key_exchange():
            self.establish_connection()

    def update_keys(self):
        new_key = generate_keypair()
        self.c_priv = new_key
        self.secret = generate_shared_secret(new_key, self.s_pub)

    def needs_key_exchange(self):
        return self.s_pub is None

    def establish_connection(self):
        # We assume here that integrity/authentication is not compromised by Mallory
        # However, she's listening
        encoded_s_pub = self.broadcast(CLIENT_PUBLIC_KEY)
        self.s_pub = parse_key(encoded_s_pub)

    def update_warnings(self, msg: Message, e: Exception = None):
        if self.detected_integrity_error and not self.sent_integrity_warning:
            msg.set_integrity_warning()
        elif self.detected_general_error and not self.sent_general_warning:
            msg.set_general_warning()
        if e:
            if is_general_error(e):  # Message or ack were dropped -
                # availability error
                msg.set_general_warning()
                return
            if is_integrity_error(e):  # Server ack was forged
                msg.set_integrity_warning()
                return
            raise e

    # Do not modify this function
    def broadcast(self, payload: str) -> str:
        """Broadcasts a payload through a socket, return replies from server"""
        if not payload.strip() or sys.getsizeof(payload) > 1024:
            raise RuntimeError("Bad payload")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(payload.encode("utf-8"))

                # Wait for acknowledgment from the server
                data = s.recv(1024)
                return data.decode("utf-8")
        except Exception as e:
            return f"Error: {e}"
