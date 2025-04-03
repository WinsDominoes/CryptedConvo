from encryption import HMAC_encryptor, RSA_encryptor
import socket
import threading
import os

class Client:
    def __init__(self, HOST, PORT=9999):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server(HOST, PORT)

        self.hmac = HMAC_encryptor()
        self.rsa = RSA_encryptor()
        self.username = ''

    # Exchange RSA public keys with server
    def exchange_keys(self):
        # Send client's public key to server
        self.socket.send(self.rsa.get_public_key())
        
        # Receive server's public key
        server_key_data = self.socket.recv(4096)
        self.rsa.set_public_key(server_key_data)

    # Encrypt message with server's public key before sending
    def send_encrypted(self, message: str) -> None:
        encrypted = self.rsa.encrypt_message(message)
        self.socket.send(encrypted)


    # Handle login/registration with HMAC authentication
    def handle_authentication(self):
        while True:
            print("\n1. LOGIN")
            print("2. REGISTER")
            print("3. EXIT")
            choice = input("Choose option (1-3): ").strip()

            if choice == '1':
                err = self.handle_login()
            elif choice == '2':
                err = self.handle_register()
            elif choice == '3':
                self.send_encrypted("EXIT")
                os.exit(1)
            else:
                print("Invalid choice")

            if not err:
                print("Error has occured during authentication process")
                os.exit(1)

    def handle_register(self) -> bool:
        username = input("New username: ").strip()
        password = input("New password: ").strip()
        
        # Generate new salt and HMAC hash
        salt = self.hmac.generate_salt()
        password_hash = self.hmac.create_hash(password, salt)
        
        # Send encrypted registration as SINGLE packet
        reg_packet = f"REGISTER {username} {password_hash} {salt.hex()}"
        self.send_encrypted(reg_packet)
        
        # Get server response
        response = self.rsa.decrypt_message(self.socket.recv(4096))
        print(f"Server response: {response}")
        if not response.startswith('REGISTER'):
            return False

        self.username = username
        return True

    def handle_login(self) -> bool:
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        # Request salt from server
        self.send_encrypted(f"GET_SALT {username}")
        salt_hex = self.rsa.decrypt_message(self.socket.recv(4096))
        salt = bytes.fromhex(salt_hex)
        
        # Create HMAC hash
        password_hash = self.hmac.create_hash(password, salt)
        
        # Send encrypted credentials as SINGLE packet
        auth_packet = f"LOGIN {username} {password_hash}"
        self.send_encrypted(auth_packet)
        
        # Get server response
        response = self.rsa.decrypt_message(self.socket.recv(4096))
        print(f"Server response: {response}")
        if response.startswith('LOGIN'):
            return False

        self.username = username
        return True

     # Receive messages
    def receive_messages(self):
        while True:
            try:
                encrypted_data  = self.socket.recv(4096)
                if not encrypted_data :
                    raise ConnectionError("Server disconnected")
                
               # Decrypt using client's private key
                message = self.rsa.decrypt_message(encrypted_data )
                
                # Parse message type
                if message.startswith("USER_OFFLINE"):
                    _, user = message.split(maxsplit=1)
                    print(f'{user} is offline')
                elif message.startswith("NOTFOUND"):
                    _, msg = message.split(maxsplit=1)
                    print(f'{msg}')
                elif message.startswith("@"):
                    user = message[1:].split(maxsplit=1)[1]
                    print(f"\n[Incoming] {user}: {message.split(maxsplit=1)[2]}\n> ", end='')
                elif message.startswith("LISTED"):
                    self.handle_command("\n" + message[6:])
                else:
                    print(f"\n[System] {message}\n> ", end='')

            except ConnectionResetError:
                print("\nServer connection lost")
                os._exit(1)
            except Exception as e:
                print(f"\nDecryption error: {e}")
                continue

     # Establish connection with server and exchange keys
    def start(self):
        try:
            self.socket.connect((self.host, self.port))
            print("Connected to server")
            self.exchange_keys()
            self.handle_authentication()

            threading.Thread(target=self.receive_messages, daemon=True).start()
            # Handle user input
            while True:
                message = input()
                
                if message.lower().startswith('/exit'):
                    self.send_encrypted("EXIT")
                    break
                elif message.lower().startswith('/help'):
                    print("\nCommands:")
                    print("/exit - Disconnect")
                    print("/list - Request online users")
                    print("/chat <user> <text_msg>\n")
                elif message.lower().startswith('/list'):
                    self.send_encrypted(f"LIST")
                elif message.lower().startswith('/send'):
                    self.send_encrypted(f"@{message.split(maxsplit=2)[1]} {message.split(maxsplit=2)[2]}")
                else:
                    self.send_encrypted(message)
        except ConnectionRefusedError:
            print("Server unavailable")
        finally:
            self.socket.close()

if __name__ == "__main__":
    client = Client()
    client.start()