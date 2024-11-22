import socket, sys
import tkinter as tk
import crypto
from keys import CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY
from crypto import (
    parse_key,
    generate_shared_secret,
    generate_keypair,
    serialize_key,
    derive_auth_key,
    derive_enc_key,
    InvalidNonceError,
    InvalidHashError,
    DroppedMessageError,
    IntegrityError,
)
import os
from json import JSONDecodeError
from message import Message

HOST = "127.0.0.1"  # Replace with the remote server's IP address. Do not change unless testing on two different
# devices.
# You can run server_wrapper.py on another terminal on the same device for development purposes.
PORT = 65431  # Port the server is listening on
TIMEOUT = 20  # 20 second timeout
MAX_RETRIES = 5


class VPN_CLIENT:
    def __init__(self):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.s_pub = (
            None  # Server public key, set only when the connection is established
        )
        self.c_priv = parse_key(CLIENT_PRIVATE_KEY)  # Client private/public keypair
        self.nonce = 0
        self.detected_integrity_error = False
        self.detected_general_error = False
        self.sent_integrity_warning = False
        self.sent_general_warning = False

        # for debugging only: (TODO delete)
        filename = os.path.join(os.path.dirname(__file__), "debug.txt")
        self.output_file = open(filename, "a")

    def needs_key_exchange(self):
        return self.s_pub is None

    def establish_connection(self) -> bool:
        # We assume here that integrity/authentication is not compromised by Mallory
        # However, she's listening
        encoded_s_pub = self.broadcast(CLIENT_PUBLIC_KEY)
        self.s_pub = parse_key(encoded_s_pub)
        return True

    def send_message(self, message: str, output: tk.Label) -> None:
        """Sends a message and gives the output to a tkinter label"""
        if self.needs_key_exchange():
            self.debug("Exchanging keys...")
            self.establish_connection()

        new_key = generate_keypair()
        self.c_priv = new_key
        if self.s_pub is None:
            raise Exception("No server public key stored! This is likely a dev error.")

        secret = generate_shared_secret(new_key, self.s_pub)
        msg = Message(
            self.nonce,
            message,
            derive_auth_key(secret),
            derive_enc_key(secret),
            new_key,
        )

        # A call to this function might be for sending a warning
        if self.detected_integrity_error and not self.sent_integrity_warning:
            msg.set_integrity_warning()
        elif self.detected_general_error and not self.sent_general_warning:
            msg.set_general_warning()

        output.config(text="Encrypting message")
        message_to_send = msg.prepare_for_sending()

        output.config(text="Sending message...")
        self.debug(
            "client sending message "
            + message[:-1]
            + " with nonce "
            + str(self.nonce)
            + "\n"
        )
        ack = self.broadcast(message_to_send)
        try:
            self.handle_response_message(ack, output)
        except (
            DroppedMessageError,
            InvalidNonceError,
        ):  # Message or ack were dropped - availability error
            self.debug("client received empty ack or replay, resending\n")
            msg.set_general_warning()
            self.resend(msg, output)
        except (IntegrityError, JSONDecodeError):  # Server ack was forged
            self.debug("client received invalid ack, resending")
            msg.set_integrity_warning()
            self.resend(msg, output)

    def handle_response_message(self, server_m: str, output: tk.Label) -> None:
        server_nonce = self.nonce + 1

        self.debug("client expecting nonce " + str(server_nonce) + "\n")
        ack_dict = Message.deserialize_payload(server_m)
        print(ack_dict)
        new_s_pub = Message.get_new_pub_key(ack_dict)
        secret = generate_shared_secret(self.c_priv, crypto.parse_key(new_s_pub))
        msg = Message.verify_and_parse(
            ack_dict, derive_auth_key(secret), derive_enc_key(secret), server_nonce
        )
        plaintext = msg.decrypt(derive_enc_key(secret))
        self.debug("client received " + plaintext + "\n")
        self.s_pub = crypto.parse_key(new_s_pub)
        self.nonce = server_nonce + 1
        output.config(text="Message sent!")

    def resend(self, msg: Message, output: tk.Label) -> None:
        """Resends msg after first attempt failed, this time with an availability warning. Tries MAX_RETRIES times."""
        # This function is crucial - we can't use send_message, because we must keep the original ciphertext
        self.debug("client resending\n")
        message_to_send = msg.prepare_for_sending()  # Does not re-encrypt
        for _ in range(MAX_RETRIES):
            try:
                ack = self.broadcast(message_to_send)
                self.handle_response_message(ack, output)
                return
            except (
                DroppedMessageError,
                InvalidNonceError,
            ):  # Message or ack were dropped - availability error
                self.debug("client received empty ack, resending\n")
                msg.set_general_warning()
            except (IntegrityError, JSONDecodeError):  # Server ack was forged
                self.debug("client received invalid ack, resending")
                msg.set_integrity_warning()

    def send_integrity_warning(self, output: tk.Label) -> None:
        if not self.sent_integrity_warning:
            self.detected_integrity_error = True
            self.send_message("", output)
            self.sent_integrity_warning = True  # this is after it's been acked

    def send_general_warning(self, output: tk.Label) -> None:
        if not self.sent_general_warning:
            self.detected_general_error = True
            self.send_message("", output)
            self.sent_general_warning = True  # this is after it's been acked

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

    # TODO delete this:
    def debug(self, message: str) -> None:
        self.output_file.write(message)
        self.output_file.flush()
