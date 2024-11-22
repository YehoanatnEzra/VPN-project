from json import JSONDecodeError

from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128, SHA256, HMAC
from Crypto.Protocol.DH import key_agreement
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import json
import crypto
from crypto import serialize_key, dict_to_jsonb, generate_shared_secret, derive_auth_key, derive_enc_key, \
    InvalidHashError, InvalidNonceError, compute_hmac, InvalidAckError, ForgedMessageError
from enum import Enum

# =========================================================================================== #
"""Message types:
Attention that a message with availability error might have relevant text (if it's a resend from the client),
and might not (if it's a notification following an error in an ack detected by client)
whereas a message of type integrity error is always an empty message"""
GENERAL = 1
AVAILABILITY_WARNING = 2
INTEGRITY_WARNING = 3
# =========================================================================================== #

KEYWORD_FOR_FORGED = "nack"

class Message:
    def __init__(self, nonce: int, text: str, auth_key: bytes, enc_key: bytes, new_pub_key: ECC.EccKey,
                 msg_type: int = GENERAL, encrypted: bool = False, iv=''):
        """
        Method instantiates a new message.

        Args:
            nonce (int): the nonce used to id the message
            text (str): the text to be sent in the message
            auth_key (bytes): the auth key used to authenticate the message
            enc_key (bytes): the encryption key used to encrypt the message
            new_pub_key (ECC.EccKey): the new key to be sent in the message
            msg_type (int, optional): MSG_TYPE_GENERAL or MSG_TYPE_ERROR. Defaults to MSG_TYPE_GENERAL.
            encrypted (bool): indicator of whether the text is encrypted

        Returns:
            New Message object
        """
        self.type = msg_type
        self.text = text
        self.iv = iv
        self.encrypted = encrypted
        self.nonce = nonce
        self.auth_key = auth_key
        self.enc_key = enc_key
        self.new_p_key = new_pub_key

    def prepare_for_sending(self) -> str:
        """returns a formatted and encrypted message as a string, ready to send"""
        if not self.encrypted:
            self.iv, self.text = crypto.encrypt(self.text, self.enc_key)
            self.encrypted = True
        _, pubk = serialize_key(self.new_p_key)

        body = {
            "type": self.type,
            "text": self.text,
            "iv": self.iv,
            "nonce": self.nonce,
            "new_pub_key": pubk,
        }

        hmac = HMAC.new(self.auth_key, dict_to_jsonb(body), digestmod=SHA256).hexdigest()
        payload = {"body": body, "hmac": hmac}

        return json.dumps(payload)

    def decrypt(self, enc_key: bytes) -> str:
        """
        Decrypts the text in a message using the given encryption key.
        """
        if not self.encrypted:
            return self.text
        self.text = crypto.decrypt(bytes.fromhex(self.text), bytes.fromhex(self.iv), enc_key)
        self.encrypted = False
        return self.text

    @staticmethod
    def get_new_pub_key(data: dict) -> str:
        """
        Returns the new public key from a dictionary representation of the message object.
        """
        return data.get("body").get("new_pub_key")

    @staticmethod
    def deserialize_payload(payload: str) -> dict:
        """
        Reconstitutes a serialized object into a dictionary, the dictionary object can be passed to verify_and_parse
        to be reconstituted into a message object.
        """
        if not payload:
            # Empty payload is a Mallory drop
            raise InvalidAckError
        if payload == KEYWORD_FOR_FORGED:
            raise ForgedMessageError
        dict_to_ret = json.loads(payload)
        if not verify_dict_structure(dict_to_ret):
            raise JSONDecodeError
        return dict_to_ret

    @staticmethod
    def extract_text(data: dict) -> str:
        return data.get("body").get("text")

    @staticmethod
    def verify_and_parse(data: dict, auth_key: bytes, enc_key: bytes, expected_nonce: int) -> "Message":
        """
        This method assumes the data is encrypted.
        Takes in a dictionary representation of a message and returns a message object.
        """
        msg_body = data.get("body")
        hmac = compute_hmac(auth_key, dict_to_jsonb(msg_body))

        try:
            hmac.hexverify(data.get("hmac"))
        except ValueError:
            raise InvalidHashError(data.get("hmac"))

        if expected_nonce != msg_body.get("nonce"):
            raise InvalidNonceError(msg_body.get("nonce"), expected_nonce)
        return Message(msg_body.get("nonce"),
                       msg_body.get("text"),
                       auth_key,
                       enc_key,
                       msg_body.get("new_pub_key"),
                       msg_body.get("type"),
                       True, msg_body.get("iv"))

    def set_availability_warning(self) -> None:
        if self.type == INTEGRITY_WARNING:
            raise Exception("The message type is INTEGRITY_WARNING, so it can't be set as availability warning.")
        self.type = AVAILABILITY_WARNING

    def set_integrity_warning(self) -> None:
        if self.type == AVAILABILITY_WARNING:
            raise Exception("The message type is AVAILABILITY_WARNING, so it can't be set as integrity warning.")
        self.type = INTEGRITY_WARNING

    def is_availability_warning(self) -> bool:
        return self.type == AVAILABILITY_WARNING

    def is_integrity_warning(self) -> bool:
        return self.type == INTEGRITY_WARNING


def verify_dict_structure(d: dict) -> bool:
    try:
        assert "body" in d
        assert "hmac" in d
        assert "type" in d["body"]
        assert "text" in d["body"]
        assert "iv" in d["body"]
        assert "nonce" in d["body"]
        assert "new_pub_key" in d["body"]
        return True
    except AssertionError:
        return False
