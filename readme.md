# There is a man in the middle!!
This project was developed as part of the final assignment in the Cybersecurity course at the University of British Columbia (UBC).
I designed and implemented a simple VPN that enables secure communication between two computers over a protected channel.
Both the client and server start with public key information about the other party, ensuring secure key exchange.
The VPN provides confidentiality, integrity, and mutual authentication, protecting data against unauthorized access and tampering.

### What is a VPN?

A Virtual Private Network (VPN) is a technology that ensures secure and private communication over the Internet by encrypting data and routing it through a remote server.
When a user connects to a VPN, their internet traffic is encrypted, preventing unauthorized parties from intercepting or reading the transmitted data.
This effectively creates a secure tunnel between the user's device and the VPN server.

As part of this assignment, I implemented a VPN under the assumption that the initial message exchanged between the client and server—containing their public keys—is authenticated.
Building on this foundation, I designed and implemented a key exchange protocol to establish a shared secret key between the two parties, as well as a communication protocol that ensures essential security properties such as confidentiality, integrity, and authentication.

### Adversary Model

In the real world, Mallory and Eve can be anyone, including your Internet Service Provider (ISP).
For this Project, I instantiated Mallory as a man in the middle by establishing the connection between client and server through Mallory.
This allows Mallory to easily see the information exchanged between client and server, *delete* packets, and *replay* packets.
Mallory will also have access to the public key information of the client and the server.



In the real world, Mallory and Eve can be anyone, including your Internet Service Provider (ISP).
For this Project, I instantiated Mallory as a man in the middle by establishing the connection between client and server through Mallory.
This allows Mallory to easily see the information exchanged between client and server, *delete* packets, and *replay* packets.
Mallory will also have access to the public key information of the client and the server.

