import socket, time

# Change the ports in vpn_client.py so that client -> mitm -> server
# Addresses and ports for the MITM
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 65431
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = 65432

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

# Buffer size for receiving data
BUFFER_SIZE = 4096
DELAY = 0.5  # 0.5-second delay

def handle_client(client_socket):
    try:
        # Receive data from the client
        client_data = client_socket.recv(BUFFER_SIZE)
        if not client_data:
            print(f"{OKGREEN}[-] No data received from client.{ENDC}")
            return

        print(f"{OKGREEN}[>] Received from client:{ENDC} {client_data}")

        # TODO Maybe do something here idk

        # Forward the data to the target server
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_socket.connect((FORWARD_IP, FORWARD_PORT))
        forward_socket.sendall(client_data)

        # Receive response from the target server
        server_response = forward_socket.recv(BUFFER_SIZE)
        print(f"{OKBLUE}[<] Received from server:{ENDC} {server_response}")

        # Send the response back to the client
        client_socket.sendall(server_response)

    except Exception as e:
        print(f"[-] Error occurred while handling client: {e}")
    finally:
        # Close the forward and client sockets
        forward_socket.close()
        client_socket.close()

def mitm_proxy():
    try:
        # Create a listening socket for incoming connections
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.bind((LISTEN_IP, LISTEN_PORT))
        listen_socket.listen(5)
        print(f"[*] Listening on {LISTEN_IP}:{LISTEN_PORT}")

        while True:
            # Accept a new connection from a client
            client_socket, client_addr = listen_socket.accept()
            print(f"{HEADER}[+] Accepted connection from {client_addr}{ENDC}")

            # Handle the client in a separate function
            handle_client(client_socket)

    except Exception as e:
        print(f"[-] Error occurred in proxy: {e}")
    finally:
        listen_socket.close()

if __name__ == "__main__":
    mitm_proxy()
