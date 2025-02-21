# There is a man in the middle!!
This project was developed as part of the final assignment in the Cybersecurity course at the University of British Columbia (UBC).
I designed and implemented a simple VPN that enables secure communication between two computer and server over a protected channel.
Both the client and server start with public key information about the other party, ensuring secure key exchange.
The VPN provides confidentiality, integrity, and mutual authentication, protecting data against unauthorized access and tampering.

### What is a VPN?

A Virtual Private Network (VPN) is a technology that ensures secure and private communication over the Internet by encrypting data and routing it through a remote server.
When a user connects to a VPN, their internet traffic is encrypted, preventing unauthorized parties from intercepting or reading the transmitted data.
This effectively creates a secure tunnel between the user's device and the VPN server.

As part of this assignment, I implemented a VPN under the assumption that the initial message exchanged between the client and server—containing their public keys is authenticated.
Building on this foundation, I designed and implemented a key exchange protocol to establish a shared secret key between the two parties, as well as a communication protocol that ensures essential security properties such as confidentiality, integrity, and authentication.

### Adversary Model

In the real world, Mallory and Eve can be anyone, including your Internet Service Provider (ISP).
For this Project, I instantiated Mallory as a man in the middle by establishing the connection between client and server through Mallory.
This allows Mallory to easily see the information exchanged between client and server, *delete* packets, and *replay* packets.
Mallory will also have access to the public key information of the client and the server.

### Key Agreement Protocol
New keys can be generated by running the "generate_keys.py" script in my repository, then updating keys.py with
the values output by that script.
For the first exchange, the client and the server exchange their ECC public keys as plaintexts. 
Since I assumped that this interaction is uninterrupted, I can be sure that the client and the server exchange authentic
public keys. I use the DH protocol to generate a shared 𝑆𝐸𝐶𝑅𝐸𝑇. Each side computes a SHA-256 hash on a
concatenation of 𝑆𝐸𝐶𝑅𝐸𝑇 with each of the strings "𝑒𝑛𝑐" and "𝑎𝑢𝑡ℎ", to generate two 256-bit AES keys 𝐾_enc and
k_auth (encryption and authentication keys respectively) to separate concerns. This protocol is protected against MitM attacks, since the adversary doesn’t have one of the private keys to generate 𝑆𝐸𝐶𝑅𝐸𝑇, and therefore can’t compute the keys. Also, because SHA-256 is a strong hash function, even if an adversary gets ahold of one of the encryption key or the authentication key, they can’t derive the other key from it.


### Communication Procatol
As a base protocol I use the OTR Rachet with three message types, one for user-generated messages and the two other for integrity warnings and general warnings.
After the key agreement, the server and the client both have their first 𝐾 and key pair. We use k_𝑒𝑛𝑐 to encrypt the messages using AES-CBC (with an IV in plaintext alongside the encrypted message) and k_auth to authenticate them by generating an HMAC of the warnings, encrypted message, IV, nonce, and the new public key together. Along with each message, I include the warnings, IV, nonce, and the new public key as plaintext. The new public key is included in every message and signed using the HMAC, ensuring that even if it is modified in
transit, such changes will be detected by the receiving party during HMAX verification. Since the public key is signed, it is safe to allow modification during transit, and these modifications don't compromise security. With every message exchange we derive a new 𝐾_enc anf k_autt key pair the same way as in the key agreement protocol.

This protocol provides confidentiality because the adversary can’t get access to the keys and our encryption function is strong. The HMAC provides integrity and authentication because the adversary does not have 𝐾.𝑎𝑢𝑡ℎ. k_auth is used for integrity by generating an HMAC from Q and comparing it to the HMAC provided in the payload to ensure the message hasn't been tampered with, and it ensures authentication by using it to verify that the messages were only sent by the parties participating in the specific session. Because either party can generate an HMAC, repudiation is provided. The HMAC is validated before decryption to ensure that we comply with the “verify first” principle. To protect against replay attacks and ensure message uniqueness, we implemented a nonce-based logic alongside a hashing message mechanism. The server accepts any nonce that is greater than the last nonce it responded to, ensuring that every message from the client is unique. This approach prevents replayed messages by rejecting nonces that have already been used, allows the server to handle dropped messages gracefully by accepting retries with higher nonces, and simplifies validation by guaranteeing messages are processed in an order
defined by their nonce. To further strengthen replay protection, we hash message identifiers and store these hashes in a set. This hash acts as a unique fingerprint for each message and enables the server to detect replay attack attempts.
Additionally the server sends acknowledgements to detect message drops. We issue a warning for every integrity and general issue on the server side. Symmetric encryption with AES ensures efficient communication. Using an HMAC rather than a MAC ens

### How to set up the code
The required packages can be found in the requirements.txt file.
To run the project, the port in the server, on which the server is listening and the port in the client on which the server is listening must be configured to the same port. After that you can run python3 server_wrapper.py, and python3 client_wrapper.py in two different terminals.
The legitimate messages and the security warnings will be logged in server_output.txt
