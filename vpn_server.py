from keys import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from crypto import parse_key, deserialize_payload, generate_shared_secret, \
    derive_auth_key, verify_and_parse_payload, decrypt, generate_keypair, serialize_payload, derive_enc_key, InvalidNonceError, InvalidHashError
import os
from json import JSONDecodeError


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

    def encrypt(self, response) -> str:
        """encrypts the response for the client, returns a formatted and plaintext-encrypted message"""
        new_key = generate_keypair()
        secret = generate_shared_secret(new_key, self.c_pub)
        payload = serialize_payload(response, self.nonce, new_key, derive_auth_key(secret), derive_enc_key(secret))

        self.nonce += 1
        self.s_priv = new_key

        return payload

    def receive(self, ciphertext: str) -> str:
        print(f"Server received: {ciphertext}")

        if self.needs_key_exchange():
            self.__debug("First message. Assuming key exchange is taking place.")
            # assume the first message is the initial pub key from the client
            self.c_pub = parse_key(ciphertext)

            self.output(SERVER_PUBLIC_KEY)
            return SERVER_PUBLIC_KEY

        try:
            payload = verify_and_parse_payload(ciphertext, self.nonce, self.s_priv)

            new_c_pub, request, iv, secret = payload
            message = decrypt(request, iv, derive_enc_key(secret))
            self.output(message)
            self.c_pub = new_c_pub
            self.nonce += 1

            print(f"client message: {message}")
            # TODO: do something with the request; we need to discuss how to react on requests and which requests we are expecting
            return self.encrypt("ack")

        # TODO: handle invalid messages according to the Error raised; we need to discuss how to handle invalid messages
        #       maybe outsource to a separate function
        except InvalidHashError:
            return self.encrypt("Message is invalid because of the HMAC")
        except InvalidNonceError:
            return self.encrypt("Message is invalid because of the nonce")
        except JSONDecodeError:
            return self.encrypt("Message is invalid because its format")

    def output(self, message: str) -> None:
        """You should not need to modify this function.
        Output whatever the client typed into the textbox as an argument to this function
        """
        self.__debug("Server sending: ", message)
        self.output_file.write(message)
        self.output_file.flush()
