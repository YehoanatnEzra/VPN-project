from keys import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from crypto import parse_key, generate_shared_secret, derive_auth_key, generate_keypair, derive_enc_key, \
    InvalidNonceError, InvalidHashError
import os
from json import JSONDecodeError
from message import Message, KEYWORD_FOR_FORGED


class VPN_SERVER:
    def __init__(self, output_file):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.c_pub = None  # Client public key, set only when the connection is established

        self.s_priv = parse_key(SERVER_PRIVATE_KEY)  # Server private/public keypair
        self.nonce = 0
        self.output_file = output_file
        self.output_file.truncate(0)  # Clear file content (new session)
        self.logged_integrity_warning = False
        self.logged_availability_warning = False
        self.ciphertext_log = set()

        # for debugging only: (TODO delete)
        filename = os.path.join(os.path.dirname(__file__), "debug.txt")
        self.debug_file = open(filename, "a")
        self.debug_file.truncate(0)

    def needs_key_exchange(self):
        """Used to check if this is the first message, guaranteed to be untampered with"""
        return self.c_pub is None

    def receive(self, ciphertext: str) -> str:
        """processes the ciphertext and returns an ack string ready to be sent to the client"""
        if self.needs_key_exchange():
            # assume the first message is the initial pub key from the client
            self.c_pub = parse_key(ciphertext)
            return SERVER_PUBLIC_KEY

        plaintext = " "
        try:
            self.debug("server expecting nonce " + str(self.nonce) + "\n")
            client_mes_dict = Message.deserialize_payload(ciphertext)
            self.debug(str(client_mes_dict) + "\n")
            self.check_for_replay(client_mes_dict)  # This must happen before verification
            new_s_pub = Message.get_new_pub_key(client_mes_dict)
            secret = generate_shared_secret(self.s_priv, parse_key(new_s_pub))
            msg = Message.verify_and_parse(client_mes_dict, derive_auth_key(secret), derive_enc_key(secret), self.nonce)
            plaintext = msg.decrypt(derive_enc_key(secret))
            self.debug("server received message " + plaintext[:-1] + " with correct nonce\n")
            self.log_content(plaintext)
            self.log_warnings(msg)  # Log warnings detected by client
            self.c_pub = parse_key(new_s_pub)
            self.nonce += 1

        # Log warnings detected by server
        except (InvalidHashError, JSONDecodeError) as e:  # Integrity
            self.debug("server exception: " + str(e) + "\n")
            self.debug("integrity server\n")
            self.log_integrity_warning()
            self.debug("sending empty string\n")
            return KEYWORD_FOR_FORGED  # notify client that message was forged, so it can resend
        except InvalidNonceError:  # Replay
            self.debug("availability server\n")
            self.log_availability_warning()

        self.debug("server nonce: " + str(self.nonce) + "\n")
        return self.send_ack("ack for " + plaintext[:-1] + " with nonce " + str(self.nonce) + "\n")

    def send_ack(self, message_text: str = "ack") -> str:
        """
        Creates a new encrypted message to be sent to the client according to communication protocol.
        It generates a new key pair, derives encryption and authentication keys using a shared secret, and constructs
        a serialized message object.

        Parameters:
            message_text (str): The content of the message to be sent to the client. Defaults to "ack".
        Returns:
            str: A serialized string (JSON format) representing the constructed message, ready to be sent to the client.
        """
        self.debug("server sending " + message_text)
        new_key = generate_keypair()
        secret = generate_shared_secret(new_key, self.c_pub)
        msg = Message(self.nonce, message_text, derive_auth_key(secret), derive_enc_key(secret), new_key)
        message_to_send = msg.prepare_for_sending()
        self.s_priv = new_key
        self.nonce += 1
        return message_to_send

    def check_for_replay(self, data: dict):
        text = Message.extract_text(data)
        if text in self.ciphertext_log:
            self.debug("replay found\n")
            raise InvalidNonceError
        self.ciphertext_log.add(text)

    def output(self, message: str) -> None:
        """You should not need to modify this function.
        Output whatever the client typed into the textbox as an argument to this function
        """
        self.output_file.write(message)
        self.output_file.flush()

    def log_availability_warning(self):
        if not self.logged_availability_warning:
            self.output("This is an availability warning.\n")
            self.logged_availability_warning = True

    def log_integrity_warning(self):
        if not self.logged_integrity_warning:
            self.output("This is an integrity warning.\n")
            self.logged_integrity_warning = True

    def log_content(self, content: str) -> None:
        if content:  # Some messages will be empty with just warnings, ignore them when logging content
            self.output(content)

    def log_warnings(self, msg: Message) -> None:
        if msg.is_availability_warning():
            self.log_availability_warning()
        elif msg.is_integrity_warning():
            self.log_integrity_warning()

    # TODO delete this:
    def debug(self, message: str) -> None:
        self.debug_file.write(message)
        self.debug_file.flush()
