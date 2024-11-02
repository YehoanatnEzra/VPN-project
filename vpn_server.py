from keys import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from crypto import parse_key
import os


class VPN_SERVER:
    def __init__(self, output_file):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.c_pub = (
            None  # Client public key, set only when the connection is established
        )
        self.s_priv = parse_key(SERVER_PRIVATE_KEY)  # Server private/public keypair
        self.nonce = 0
        self.output_file = output_file
        self.debug_enabled = "DEBUG" in os.environ

        self.__debug("Debug mode enabled.")

    def __debug(self, *args):
        if self.debug_enabled:
            print("DEBUG:", *args)

    def needs_key_exchange(self):
        """Used to check if this is the first message, guaranteed to be untampered with"""
        return self.c_pub is None

    def receive(self, ciphertext: str) -> str:
        print(f"Server received: {ciphertext}")

        if self.needs_key_exchange():
            self.__debug("First message. Assuming key exchange is taking place.")
            # assume the first message is the initial pub key from the client
            self.c_pub = parse_key(ciphertext)

            self.output(SERVER_PUBLIC_KEY)
            return SERVER_PUBLIC_KEY

        # TODO: ensure the json is correctly formatted
        # validate the hmac with validate_payload_hmac(...)
        # parse the payload with parse_payload(...) using the correct params
        # update the ratchet state
        # check/increment the nonce
        # decrypt the ciphertext with decrypt(...) using the returned values from parse_payload(...)

        self.output(ciphertext)

        return ciphertext

    def output(self, message: str) -> None:
        """You should not need to modify this function.
        Output whatever the client typed into the textbox as an argument to this function
        """
        self.__debug("Server sending: ", message)
        self.output_file.write(message)
        self.output_file.flush()
