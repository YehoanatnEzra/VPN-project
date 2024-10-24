from keys import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY

class VPN_SERVER:
    def __init__(self, output_file):
        self.output_file = output_file

    def receive(self, ciphertext: str) -> str:
        print(f"Server received: {ciphertext}")
        # TODO Your code here
        # decrypting here seems like a good idea

        self.output(ciphertext)
        
        return ciphertext
    
    def output(self, message: str) -> None: 
        """You should not need to modify this function. 
        Output whatever the client typed into the textbox as an argument to this function
        """
        self.output_file.write(message)
        self.output_file.flush()