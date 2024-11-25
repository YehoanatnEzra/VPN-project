from keys import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from crypto import *
import os
from json import JSONDecodeError
from message import Message

ACK_FOR_FORGED = "what goes around comes around: invalid message, invalid response :)"
ACK_FOR_REPLAY_OR_DROP = "go away, mallory"


class VPN_SERVER:
    def __init__(self, output_file):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.c_pub = None  # Client public key, set only when the connection is established
        self.message_cache = set()  # To detect replays
        self.s_priv = parse_key(SERVER_PRIVATE_KEY)  # Server private/public keypair
        self.nonce = 0
        self.output_file = output_file
        self.output_file.truncate(0)  # Clear file content (new session)
        self.logged_integrity_warning = False
        self.logged_general_warning = False
        self.prev_s_priv = None  # In case the client resends, and we need to verify with old keys

    def receive(self, ciphertext: str) -> str:
        """processes the ciphertext and returns an ack string ready to be sent to the client"""
        if self.needs_key_exchange():
            # assume the first message is the initial pub key from the client
            self.c_pub = parse_key(ciphertext)
            return SERVER_PUBLIC_KEY
        plaintext = " "
        try:
            self.process_ciphertext(ciphertext)
        except Exception as e1:  # Detected security issue
            if is_integrity_error(e1):  # Suspected as integrity, but let's make sure
                try:
                    self.process_ciphertext_with_old_keys(ciphertext)  # Maybe a resend from the client?
                except Exception as e2:
                    return self.replay_or_forge(ciphertext, e2)
            elif is_general_error(e1):
                self.log_general_warning()
                return ACK_FOR_REPLAY_OR_DROP
            else:
                raise e1
        return self.send_ack("ack for " + plaintext[:-1])

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
        new_key = generate_keypair()
        secret = generate_shared_secret(new_key, self.c_pub)
        msg = Message(self.nonce, message_text, secret, new_key)
        message_to_send = msg.prepare_for_sending()
        self.prev_s_priv = self.s_priv
        self.s_priv = new_key
        self.cache(message_to_send)  # so that acks are also never replayed
        return message_to_send

    def process_ciphertext(self, ciphertext):
        client_mes_dict = Message.deserialize_payload(ciphertext)
        new_s_pub = Message.get_new_pub_key(client_mes_dict)
        secret = generate_shared_secret(self.s_priv, parse_key(new_s_pub))
        msg = Message.verify_and_parse(client_mes_dict, secret, self.nonce)
        plaintext = msg.msg_decrypt(derive_enc_key(secret))
        self.log_content(plaintext)
        self.log_warnings(msg)  # Log warnings detected by client
        self.c_pub = parse_key(new_s_pub)
        self.cache(ciphertext)
        self.nonce = msg.nonce + 1
        return ciphertext

    def process_ciphertext_with_old_keys(self, ciphertext):
        client_mes_dict = Message.deserialize_payload(ciphertext)
        new_s_pub = Message.get_new_pub_key(client_mes_dict)
        secret = generate_shared_secret(self.prev_s_priv, parse_key(new_s_pub))
        msg = Message.verify_and_parse(client_mes_dict, secret, self.nonce)
        self.log_warnings(msg)  # Log warnings detected by client
        self.cache(ciphertext)
        self.nonce = msg.nonce + 1
        self.s_priv = self.prev_s_priv  # set private key to the previous one

    def replay_or_forge(self, ciphertext, e):
        """Identifies if the ciphertext is a replay or a forge, and returns correct ack"""
        if is_integrity_error(e):  # Not a resend from the client, maybe a Mallory replay?
            if self.is_replay(ciphertext):
                self.log_general_warning()
                return ACK_FOR_REPLAY_OR_DROP
            # truly a forged message
            self.log_integrity_warning()
            return ACK_FOR_FORGED
        if is_general_error(e):
            self.log_general_warning()
            return ACK_FOR_REPLAY_OR_DROP
        raise e

    def cache(self, ciphertext):
        msg_hash = SHA256.new(ciphertext.encode("utf-8")).digest()
        self.message_cache.add(msg_hash)

    def is_replay(self, ciphertext):
        msg_hash = SHA256.new(ciphertext.encode("utf-8")).digest()
        return msg_hash in self.message_cache

    def needs_key_exchange(self):
        """Used to check if this is the first message, guaranteed to be untampered with"""
        return self.c_pub is None

    def output(self, message: str) -> None:
        """You should not need to modify this function.
        Output whatever the client typed into the textbox as an argument to this function
        """
        self.output_file.write(message)
        self.output_file.flush()

    def log_general_warning(self):
        if not self.logged_general_warning:
            self.output("Mallory detected: General warning!\n")
            self.logged_general_warning = True

    def log_integrity_warning(self):
        if not self.logged_integrity_warning:
            self.output("Mallory detected: Integrity warning!\n")
            self.logged_integrity_warning = True

    def log_content(self, content: str) -> None:
        if content:  # Some messages will be empty with just warnings, ignore them when logging content
            self.output(content)

    def log_warnings(self, msg: Message) -> None:
        if msg.is_general_warning():
            self.log_general_warning()
        if msg.is_integrity_warning():
            self.log_integrity_warning()
