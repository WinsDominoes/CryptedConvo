import socket
import threading
import os
from encryption import RSA_encryptor

class Server:
    def __init__(self, HOST='localhost', PORT=9999):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(1.0)
        self.host = HOST
        self.port = PORT
        self.clients = {}  # username: {socket, public_key, salt, password_hash}

    # Start the server to accept connectionsss
    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)  # Listen for up to 5 clients
        print(f"Server started at {self.host}:{self.port}")

        try:
            while True:
                try:
                    client_socket, client_address = self.socket.accept()
                    print(f"New connection from {client_address}")
                    threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
                except socket.timeout:
                    continue  # Just re-loop and wait for the next connection
        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()
            print("Server Socket closed.")

    # Handle client communication
    def handle_client(self, client_socket):

        # Exchange RSA public keys
        rsa = self.exchange_keys(client_socket)

        # Handle authentication (Login/Registration)
        self.handle_authentication(client_socket, rsa)
        
        while True:
            try:
                message = rsa.decrypt_message(client_socket.recv(4096))
                print(f"Received message: {message}")
                self.handle_message(client_socket, message, rsa)

            except Exception as e:
                print(f"Error: {e}")
                self.remove_client(client_socket)
                break

    # RSA Key exchange between server and client
    def exchange_keys(self, client_socket):
        rsa = RSA_encryptor()

        # Receive client's public key
        client_pub_key = client_socket.recv(4096)
        rsa.set_public_key(client_pub_key)

        # Send server's public key
        client_socket.sendall(rsa.get_public_key())

        print("Exchange success")
        return rsa

    # Handle authentication - Login or Register
    def handle_authentication(self, client_socket, rsa):
        while True:
            try:
                message = rsa.decrypt_message(client_socket.recv(4096))
                print(f"Authentication message: {message}")

                if message.startswith("REGISTER"):
                    if self.handle_register(client_socket, message, rsa):
                        break
                elif message.startswith("LOGIN"):
                    if self.handle_login(client_socket, message, rsa):
                        break
                elif message.startswith("GET_SALT"):
                    self.handle_salt_request(client_socket, message, rsa)
                else:
                    print(f"Invalid message during authentication: {message}")
                    client_socket.sendall(rsa.encrypt_message("Invalid request"))
            except Exception as e:
                print(f"Authentication error: {e}")
                break

    # Handle registration
    def handle_register(self, client_socket, message, rsa):
        _, username, password_hash, salt_hex = message.split()
        salt = bytes.fromhex(salt_hex)

        # Check if the user already exists
        if username in self.clients:
            client_socket.sendall(rsa.encrypt_message(f"REGISTER FAILED {username} already exists"))
            return False

        # Save user credentials (You should ideally hash and store them in a secure database)
        self.clients[username] = {
            'socket': client_socket,
            'rsa': rsa,
            'salt': salt, 
            'password_hash': password_hash
        }
        client_socket.sendall(rsa.encrypt_message(f"REGISTER SUCCESS {username} registered"))
        return True

    # Handle login
    def handle_login(self, client_socket, message, rsa):
        _, username, password_hash = message.split()

        # Check if user exists and the hash matches
        if username not in self.clients or self.clients[username]['password_hash'] != password_hash:
            client_socket.sendall(rsa.encrypt_message("LOGIN FAILED Invalid username or password"))
            return False
        else:
            client_socket.sendall(rsa.encrypt_message(f"LOGIN SUCCESS Welcome back, {username}"))
            self.clients[username]['socket'] = client_socket
            self.clients[username]['rsa'] = rsa
            return True

    # Handle salt request for login
    def handle_salt_request(self, client_socket, message, rsa):
        _, username = message.split()

        # Check if the user exists
        if username not in self.clients:
            client_socket.sendall(rsa.encrypt_message("NOTFOUND User not found"))
        else:
            # Send the salt to the client
            salt = self.clients[username]['salt']
            client_socket.sendall(rsa.encrypt_message(salt.hex()))

    # Handle receiving messages from clients
    def handle_message(self, client_socket, message, rsa):
        if message.startswith("@"):  # Private message format: @username message
            sender_user, target_user, message_content = message[1:].split(maxsplit=2)
            self.send_private_message(sender_user, target_user, message_content, client_socket, rsa)
        elif message.startswith("LIST"):
            self.handle_list(client_socket, rsa)
        elif message.startswith("EXIT"):
            self.remove_client(client_socket)
            client_socket.close()

    # Send a private message to a specific user
    def send_private_message(self, sender_user, target_user, message, sender_socket, rsa):
        if target_user not in self.clients:
            print(f"User {target_user} not found")
            sender_socket.sendall(rsa.encrypt_message(f"NOTFOUND {target_user} not found"))
            return

        target_socket = self.clients[target_user]['socket']
        target_rsa = self.clients[target_user]['rsa']

        encrypted_message = target_rsa.encrypt_message(f"@{sender_user} {message}")
        target_socket.sendall(encrypted_message)
        sender_socket.sendall(rsa.encrypt_message(f"Message sent to {target_user}: {message}"))

    # Handle the /list command
    def handle_list(self, client_socket, rsa):
        online_users = [user for user, data in self.clients.items() if data['socket'] is not None]
        client_socket.sendall(rsa.encrypt_message(f"LISTED {', '.join(online_users)}"))

    # Remove a client from the list of connected clients
    def remove_client(self, client_socket):
        for username, data in list(self.clients.items()):
            if data['socket'] == client_socket:
                print(f"Client {username} disconnected")
                self.clients[username]['socket'] = None
                self.clients[username]['rsa'] = None
                break

if __name__ == "__main__":
    server = Server('localhost', 12345)  # Adjust with the correct host and port
    server.start()
