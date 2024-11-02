from crypto import (
    decrypt,
    derive_auth_key,
    generate_keypair,
    derive_enc_key,
    generate_shared_secret,
    parse_payload,
    serialize_key,
    parse_key,
    serialize_payload,
    validate_payload_hmac,
)


from keys import (
    SERVER_PRIVATE_KEY,
    SERVER_PUBLIC_KEY,
    CLIENT_PRIVATE_KEY,
    CLIENT_PUBLIC_KEY,
)

import json


def test_shared_secret_generation():
    """
    Ensure two randomly generated keys land on the same shared secret
    As a smoke test, ensure that rerunning the process will not generate the same shared secret
    """
    client_key, server_key = generate_keypair(), generate_keypair()
    shared_secret_1 = generate_shared_secret(client_key, server_key.public_key())

    assert shared_secret_1 == generate_shared_secret(
        server_key, client_key.public_key()
    )

    # regenerate
    client_key, server_key = generate_keypair(), generate_keypair()
    shared_secret_2 = generate_shared_secret(client_key, server_key.public_key())

    assert shared_secret_2 == generate_shared_secret(
        server_key, client_key.public_key()
    )

    # ensure different secrets
    assert shared_secret_1 != shared_secret_2


def test_symmetric_key_generation():
    """Tests generation of symmetric keys from a shared secret"""
    secret = "a top secret secret".encode("utf-8")

    assert (
        derive_enc_key(secret).hex()
        == "d5f6748f54c6e4bef54863e0fe412416af1b24c648c8741d20f6b3a243b9bf07"
    )
    assert (
        derive_auth_key(secret).hex()
        == "65e46d69442c9e490237b3c2131c742d8070f3c9b09c8a359ce9a1004ab5670d"
    )

    assert len(derive_auth_key(secret)) == 32


# uncomment this to generate new keys to put in keys.py

"""
def test_ecc_gen():
    client_key, server_key = generate_keypair(), generate_keypair()

    c_priv, c_pub = serialize_key(client_key)
    s_priv, s_pub = serialize_key(server_key)

    print(f"Client Public Key: {c_pub}")
    print(f"Client Private Key: {c_priv}")
    print()
    print(f"Server Public Key: {s_pub}")
    print(f"Server Private Key: {s_priv}")
    assert False
"""


def test_key_serialization_and_parsing():
    """Make sure that we can correctly parse and serialize the keys in keys.py"""
    c_priv = parse_key(CLIENT_PRIVATE_KEY)
    c_pub = parse_key(CLIENT_PUBLIC_KEY)

    s_priv = parse_key(SERVER_PRIVATE_KEY)
    s_pub = parse_key(SERVER_PUBLIC_KEY)

    serialized_c_priv, serialized_c_pub = serialize_key(c_priv)
    serialized_s_priv, serialized_s_pub = serialize_key(s_priv)

    assert SERVER_PRIVATE_KEY == serialized_s_priv
    assert SERVER_PUBLIC_KEY == serialized_s_pub

    assert CLIENT_PRIVATE_KEY == serialized_c_priv
    assert CLIENT_PUBLIC_KEY == serialized_c_pub

    # just for good measure, let's make sure we arent using the same keys for both ends
    assert CLIENT_PRIVATE_KEY != CLIENT_PUBLIC_KEY
    assert SERVER_PUBLIC_KEY != SERVER_PRIVATE_KEY
    assert CLIENT_PRIVATE_KEY != SERVER_PRIVATE_KEY

    # smoke test: make sure the secret is what we expect, initially
    ss = generate_shared_secret(c_priv, s_pub)
    assert (
        ss.hex() == "8ee8443885434c5bda0340b0e39735b8aecab0578ed511ccf9dd39ff022ab5e9"
    )

    assert ss == generate_shared_secret(s_priv, c_pub)


def test_payload_serialization_and_parsing():
    c_key, s_key = generate_keypair(), generate_keypair()

    ss = generate_shared_secret(c_key, s_key.public_key())

    auth_key = derive_auth_key(ss)
    enc_key = derive_enc_key(ss)

    plaintext = "hello world"
    new_pub_key = generate_keypair().public_key()

    str_payload = serialize_payload(plaintext, 42, new_pub_key, auth_key, enc_key)
    payload = json.loads(str_payload)

    assert validate_payload_hmac(payload, auth_key)
    payload["hmac"] = "invalid hmac"
    assert not validate_payload_hmac(payload, auth_key)

    ciphertext, iv, nonce, parsed_pub_key = parse_payload(payload)
    assert nonce == 42
    assert serialize_key(new_pub_key)[1] == serialize_key(parsed_pub_key)[1]

    assert decrypt(ciphertext, iv, enc_key) == plaintext
