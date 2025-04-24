from encryption import RSA_encryptor, HMAC_encryptor
import socket
import threading
import os

class Client:
    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.rsa = RSA_encryptor()
        self.hmac = HMAC_encryptor()
        self.username = ""

    def exchange_keys(self):
        """ Exchange public RSA keys between client and server. """
        # Send client's public key to server
        self.socket.send(self.rsa.get_public_key())

        # Receive server's public key
        server_public_key = self.socket.recv(4096)
        self.rsa.set_public_key(server_public_key)

    def authenticate(self):
        """ Handle the authentication (login/registration).  """
        while True:
            print("\n1. LOGIN")
            print("2. REGISTER")
            print("3. EXIT")
            choice = input("Choose option (1-3): ").strip()

            if choice == '1':
                if self.login():
                    break
            elif choice == '2':
                if self.register():
                    break
            elif choice == '3':
                self.socket.send(self.rsa.encrypt_message("EXIT"))
                os.exit(1)
            else:
                print("Invalid choice")

    def login(self):
        """ Handle login process with HMAC authentication. """
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        # Request salt from the server
        self.socket.send(self.rsa.encrypt_message(f"GET_SALT {username}"))
        salt_hex = self.rsa.decrypt_message(self.socket.recv(4096))
        salt = bytes.fromhex(salt_hex)

        # Generate HMAC hash of the password
        password_hash = self.hmac.create_hash(password, salt)

        # Send login details
        self.socket.send(self.rsa.encrypt_message(f"LOGIN {username} {password_hash}"))

        # Receive response from server
        response = self.rsa.decrypt_message(self.socket.recv(4096))
        print(f"Server response: {response}")
        if response.startswith("LOGIN SUCCESS"):
            self.username = username
            return True
        else:
            return False

    def register(self):
        """ Handle user registration process. """
        username = input("New username: ").strip()
        password = input("New password: ").strip()

        # Generate new salt and HMAC hash
        salt = self.hmac.generate_salt()
        password_hash = self.hmac.create_hash(password, salt)

        # Send registration details to the server
        self.socket.send(self.rsa.encrypt_message(f"REGISTER {username} {password_hash} {salt.hex()}"))

        # Receive response from server
        response = self.rsa.decrypt_message(self.socket.recv(4096))
        print(f"Server response: {response}")
        if response.startswith("REGISTER SUCCESS"):
            self.username = username
            return True
        else:
            return False

    def send_private_message(self, target_user, message):
        """ Send a private message to a specific user. """
        self.socket.send(self.rsa.encrypt_message(f"@{self.username} {target_user} {message}"))

    def handle_commands(self):
        """ Handle client commands like /list and /exit. """
        while True:
            message = input("> ").strip()

            if message.lower() == "/exit":
                self.socket.send(self.rsa.encrypt_message("EXIT"))
                self.socket.close()
                break
            elif message.lower() == "/list":
                self.socket.send(self.rsa.encrypt_message("LIST"))
            elif message.lower().startswith("/send"):
                _, target_user, msg = message.split(maxsplit=2)
                self.send_private_message(target_user, msg)
            else:
                self.socket.send(self.rsa.encrypt_message(message))

    def receive_messages(self):
        """ Receive and handle incoming messages from the server. """
        while True:
            try:              
                response = self.socket.recv(4096)
                if response == b'':
                    print(f"Connection error: Server closed socket")
                    self.socket.close()
                    break

                message = self.rsa.decrypt_message(response)
                if message:
                    if message.startswith("LISTED"):
                        print(f"Online users: {message[6:]}")
                    elif message.startswith("@"):
                        sender, message = message[1:].split(maxsplit=1)
                        print(f"[Private message] @{sender}: {message}")
                    else:
                        print(f"[System] {message}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def start(self):
        """ Start the client, connect to the server, and begin the communication. """
        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # Exchange RSA public keys
            self.exchange_keys()

            # Authenticate (Login or Register)
            self.authenticate()

            # Start receiving messages in a separate thread
            threading.Thread(target=self.receive_messages, daemon=True).start()

            # Handle user input commands
            self.handle_commands()

        except Exception as e:
            print(f"Connection error: {e}")
            self.socket.close()

if __name__ == "__main__":
    client = Client('localhost', 12345)
    client.start()
