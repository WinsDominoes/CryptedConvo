from src.encryption import HMAC_encryptor, RSA_encryptor
import socket
import threading

class Client:
    def __init__(self, HOST, PORT=9999):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server(HOST, PORT)

        self.hmac = HMAC_encryptor()
        self.rsa = RSA_encryptor()
        self.connected = False

    # Establish connection with server and exchange keys
    def connect_to_server(self, host, port):
        try:
            self.socket.connect((self.host, self.port))
            print("Connected to server!")
            
            # Exchange public keys with server
            self.socket.send(self.rsa.get_public_key())
            server_key = self.socket.recv(4096)
            self.rsa.set_public_key(server_key)
            
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    # Handle login/registration with HMAC authentication"""
    def authenticate(self, action, username, password):
        try:
            # Send action (LOGIN/REGISTER)
            self.socket.send(action.encode())
            
            # Create salted HMAC of credentials
            salt = HMAC_encryptor.generate_salt()
            credentials = f"{username}:{password}"
            hmac_digest = self.hmac.create_hash(credentials, salt)
            
            # Send salt|credentials|hmac
            auth_data = f"{salt.hex()}|{credentials}|{hmac_digest}"
            encrypted_auth = self.rsa.encrypt_message(auth_data)
            self.socket.send(encrypted_auth)
            
            # Get server response
            response = self.socket.recv(4096)
            decrypted_response = self.rsa.decrypt_message(response)
            return decrypted_response
        except Exception as e:
            print(f"Authentication error: {e}")
            return "AUTH_FAILED"

    # Handle outgoing encrypted messages
    def send_messages(self):
        while self.connected:
            try:
                message = input("> ")
                if message.lower() == 'exit':
                    break
                    
                encrypted_msg = self.rsa.encrypt_message(message)
                self.socket.send(encrypted_msg)
            except Exception as e:
                print(f"Sending error: {e}")
                break

    # Handle incoming encrypted messages"""
    def receive_messages(self):
        while self.connected:
            try:
                encrypted_msg = self.socket.recv(4096)
                if not encrypted_msg:
                    break
                    
                message = self.rsa.decrypt_message(encrypted_msg)
                print(f"\n[Server]: {message}")
            except Exception as e:
                print(f"Receiving error: {e}")
                break

    # Main client interface
    def start(self):
        if not self.connect_to_server():
            return
            
        while True:
            print("\n1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ")
            
            if choice == "3":
                break
                
            username = input("Username: ")
            password = input("Password: ")
            
            action = "REGISTER" if choice == "1" else "LOGIN"
            response = self.authenticate(action, username, password)
            
            if response == "AUTH_SUCCESS":
                print("Authentication successful! Start messaging (type 'exit' to quit)")
                # Start message threads
                receive_thread = threading.Thread(target=self.receive_messages)
                receive_thread.daemon = True
                receive_thread.start()
                
                self.send_messages()
                break
            else:
                print(f"Authentication failed: {response}")
                
        self.socket.close()
        print("Disconnected from server.")

if __name__ == "__main__":
    client = Client()
    client.start()