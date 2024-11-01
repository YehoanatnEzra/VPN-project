[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/u6uaLgrh)
# Assignment 5: There is a man in the middle

In this assignment, you are to develop a simple VPN that allows data to be sent from one computer to another over a protected channel. 
Both ends of the VPN (client and server) start with public key information about the other party.
You must design a key establishment protocol and a communication channel that provides confidentiality, integrity, and mutual authentication.


## Contents

* [Logistics](#logistics)
* [Assignment Description](#assignment-description)
* [Task 0: Preliminaries](#task-0-preliminaries)
* [Task 1: Protocol Design](#task-1-protocol-design)
* [Task 2: Protocol Implementation](#task-2-protocol-implementation)


## Logistics

### Group Work

This is a group assignment.
As such, it is your responsibility to clarify expectations between everyone in the group very early on.
Consider having frequent meetings or checkpoints.
Get started as early as possible.
At the end of the assignment, instructors will use the **iPeer** tool to gather feedback from each group and detect if there are people that did not cooperate.
Your grade will be affected if you refuse to work with your group.

### Task completion order, deliverables, and deadlines

This assignment is worth **250** pts (so x2.5 more compared to previous assignments).
The assignment is divided into tasks to be completed sequentially:
- **Task 0** contains the basic requirements of the assignment, and is also a preliminary task for your group to get familiar with the environment. There is no deliverable associated with this task.
- **Task 1** is the design of your VPN protocol. The deliverable is a 1-page document explaining your protocol.
    - **Task 1 deliverable deadline: Wednesday, October 30th, 2024**
    - This deliverable is worth **20 pts**
- **Task 2** is the implementation and evaluation of your VPN. The deliverables are your codebase, to be submitted using git, as well as a document explaining how to use your VPN and any changes from the document from Task 1.
    - **Task 2 deliverable deadline: Friday, November 15th, 2024**
    - This deliverable is worth **230 pts**.
    - You can get *40 bonus pts* by implementing some extra requirements.


## Assignment Description


### What is a VPN?

A Virtual Private Network (VPN) is a technology that provides a secure and private connection over the Internet by encrypting data and routing it through a remote server. 
When a user connects to a VPN, their internet traffic is encrypted, preventing anyone from reading the contents of their messages. 
This creates a private tunnel between the user's device and the VPN server.

In this assignment, you will implement a VPN where we will assume that the first message between client and server, which will be their public key exchange, is authenticated.
We will call these keys the *long-term public keys*.
Starting from this, you must design a key exchange protocol that they can use to agree on a common shared key, as well as a communication protocol that provides certain security properties.

### Adversary Model

In the real world, Mallory and Eve can be anyone, including your Internet Service Provider (ISP).
For this assignment, we will instantiate Mallory as a man in the middle by establishing the connection between client and server through Mallory.
This allows Mallory to easily see the information exchanged between client and server, *delete* packets, and *replay* packets.
Mallory will also have access to the public key information of the client and the server.
Keep this in mind when designing your protocol.


### Design Requirements
The key exchange protocol should be **secure against a man-in-the-middle attack** (MitM).
The MitM will not modify the initial long-term keys exchanged.
This means that, at the end of the exchange, only the client and the server should know their shared secret.

The communication protocol should provide the following **basic cryptographic properties**:
- **Confidentiality**: Eve should not be able to read the contents of the messages exchanged between the client and server.
- **Integrity**: if Mallory modifies any message exchanged between the client and server (and we will do this during evaluation), the other party should notice.
- **Authentication**: the client and server should be able to verify that they are talking to each other, and not a potential adversary.
You must issue a warning message through the user interface if integrity/authentication fail.

The following properties should also be provided for maximum points:
- **Replay protection**: you should detect if Mallory is replaying a message sent in the past, and issue a warning on the user interface.
- **Out-of-order arrival**: since Mallory can block and replay messages, she could change the order in which messages arrive at the server.
If she does this, the server should issue a warning.
- **Separation of duties**: you should use a different key for encryption than the one you use for authentication/integrity. It should not be trivial to derive one key from the other.
- **Communication efficiency**: you should use cryptographic techniques that are appropriate for sending large amounts of information efficiently.
- **Authenticate first**: when a party receives a message, they should be able to verify authenticity before performing any other operation.
- **Long-term keys used once per session**: you should only use the initial keys shared by client and server (long-term keys) once per session (i.e., once every time we run your program).

The following properties are *optional* and provide bonus points:
- **Forward secrecy**: if Mallory learns the key material of any party at any point during the communications, she should not be able to compromise the security of past messages she has observed.
- **Post-compromise security**: if Mallory learns the key material of any party at any point in the communication, she should not be able to compromise the security of future communications.

### Notes and restrictions

In the real world (outside this course) you should not implement a cryptographic protocol at a low level such as this by yourself.
Instead, you should rely on a package that already offers a fully tested implementation.
However, the goal of this assignment is not for you to use real-world packages (that is easy, as there is a lot of information about it on the Internet).
The goal of this assignment is for you to understand the cryptographic primitives we have seen in the classroom, and to put them together to build a bigger system.

You are allowed to use any cryptographic algorithm offered by PyCryptodome that implements the cryptographic primitives we have seen in the classroom.
This includes encryption/decryption using symmetric and public-key cryptosystems, the modes of operation we have seen (ECB, CBC, and CTR; you are *not* allowed to use authenticated encryption modes), MACs and digital signatures.
You must do some research on your own to figure out which functions of PyCryptodome you want to use.

If you are not sure whether or not you are allowed to use a certain package, please ask the instructors first.


## Task 0: Preliminaries


### Required packages

To complete this lab, you will need access to a machine with python3 and tkinter installed. 
Our evaluation environment will have the `tkinter` and `pycrypto` (PyCryptodome) packages installed.
If you are to use any other packages, please double-check with the TA, and specify your requirements with a file called `requirements.txt` in [this](https://pip.pypa.io/en/stable/reference/requirements-file-format/) format


### File structure

To begin this assignment, you will get access to a github repository which contains the following files:
- `client_wrapper.py`: This is a wrapper for your client with the `tkinter` gui. You should *not* need to modify this file.

- `server_wrapper.py`: This is a wrapper for your server. You should *not* need to modify this file.

- `vpn_client.py`: This is your implementation of the VPN client. Please do *not* modify the `broadcast()` function. The wrapper will call the `send_message()` function.

- `vpn_server.py`: This is your implementation of the VPN server. Please do *not* modify the `output()` function as this writes to the file, and we will grade the text received over your VPN.

- `keys.py`: This file contains the client and server authentication key pairs. They are currently empty. Please populate them with your keys as appropriate and note down how you generated the keys.

### How this VPN works

This VPN works by having a user input a message into the clientside interface and pressing the send button. 
This passes the message into the `VPN_Client` through the `send_message()`, along with a tkinter label to return the result of this action. 
Currently, this is passed as plaintext (you will implement the encryption) to the `broadcast()` function which will send the payload on the socket. 

You will notice the `HOST` is currently set to `127.0.0.1`. 
For testing purposes, you can leave that as this will pass it back to your own host machine. 
When grading, we will have it set to a different machine over the network. 
The `PORT` is arbitrary, you can change it to a different port if it is currently in use. 
Remember to change it on both the client and the server.

On the server side, when the wrapper receives payload on the port, the payload is passed to the `VPN_Server` through the `receive()` function. 
You must then process the payload and send a message replying to the client by the returning it in the function. 

### Running this VPN

Before you proceed with Task 1, get familiar with the different files in the repository.
Then, on your computer, run this by first `python3 server_wrapper.py`, start a new terminal, and `python3 client_wrapper.py`. Try sending a message.
It is recommended that you use a [virtual environment](https://docs.python.org/3/library/venv.html). 

## Task 1: Protocol Design

Your first task is to think about the protocol you will use for the VPN.
We will assume that the first message exchange between the client and server (i.e., the first message each way) is **authenticated** (Mallory will not interfere with it).
You must use this message to send a single key in each direction.
You can use this so that, at the end of the exchange:
- `VPN_CLIENT` has `CLIENT_PRIVATE_KEY`, `CLIENT_PUBLIC_KEY`
- `VPN_SERVER` has `SERVER_PRIVATE_KEY`, `SERVER_PUBLIC_KEY`.


Using this information, you must devise:
- A key exchange protocol that the client and server run to derive a shared secret key.
- A communication protocol that the client and server can use with their shared key to exchange information


### Deliverable (20 pts)

Your group must submit, by the due date above, a 1-page pdf file explaining your protocol design.
Anything beyond 1 page will not be graded/read.
The document must explain:
- How does your key agreement protocol work?
- Why does your key agreement protocol provide protection against a man-in-the-middle (MitM) attack?
- How does your communication protocol work? What cryptographic building blocks does it rely on?
- Why does your communication protocol provide confidentiality, integrity, and authentication?

You will only get completion marks for this deliverable, i.e., you will not be judged on whether your protocol is indeed secure.
The goal is not for you to submit a perfect foolproof protocol, but to get feedback on your protocol so that you do not spend the next two weeks implementing something that is insecure.
Use this chance to get as much feedback from the instructors as possible.
The instructors will meet with groups to provide feedback if they spot any red flags.

The following is the grading criteria.

| Criteria    | Points |
| -------- | ------- |
| Key agreement protocol clearly explained | 5 pts  |
| Key agreement protocol defense against MitM explained | 5 pts |
| Communication protocol clearly exlained    | 5 pts |
| Communication protocol confidentiality, integrity, and authentication are explained | 5 pts |

## Task 2: Protocol Implementation

Your next task is to implement the protocol.
Distribute the tasks between everyone in the group as you see fit.
Get started early, as you will need to debug and test your implementation.
Take into account the note above about restrictions.



### Deliverable (230 pts)

Your group must submit, by the due date above:
- A pdf document that extends the one from Task 1. This document must contain:
    - An updated protocol description, explaining why your protocol provides all the security properties in the [requirements](#requirements) section.
    - A changelog summarizing the changes from the original protocol description in the first deliverable.
    - Any details necessary to set up your code (if needed). This includes special packages needed (requires prior instructor approval).
- Your code submission in a git repository by the deadline above. Write access will automatically end at 11:59pm.

The following table explains how we will grade this second deliverable:

| Criteria    | Points |
| -------- | ------- |
| **Document (30 pts)**
| Document includes all sections above, with the respective information correctly explained. | 20 pts
| Document is well-written (grammar, clarity, organization). | 10 pts
| **Code (200 pts)** |
| Key agreement protects against MitM | 30 pts |
| Confidentiality | 30 pts |
| Integrity and Authentication | 20 pts |
| Replay protection | 15 pts 
| Out-of-order detection | 15 pts
| Separation of duties | 15 pts
| Communication efficiency | 15 pts
| Authenticate first | 15 pts
| Long-term keys are used once | 15 pts
| Code quality, simplicity and succinct comments to help the grader | 30 pts
| **Optional (40 bonus pts)**
| Forward secrecy | 20 pts
| Post-compromise security | 20 pts
