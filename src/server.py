from database import DatabaseHandler
from encryption import RSA_encryptor
from typing import Dict
import socket
import threading

class Server:
    def __init__(self, HOST, PORT=9999):
        self.db = DatabaseHandler()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((HOST, PORT))
        self.socket.listen(5)
        
        self.clients: Dict[str, Dict] = {}  # {username: {'socket': socket, 'rsa': RSA_encryptor}}
        self.server_rsa = RSA_encryptor()
        self.server_rsa.generate_keys()
        
        print(f"Server running on {HOST}:{PORT}")
        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        while True:
            client_socket, addr = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, sock: socket.socket):
        try:
            # Key exchange
            sock.send(self.server_rsa.get_public_key())
            client_rsa = RSA_encryptor()
            client_rsa.set_public_key(sock.recv(4096))
            
            # Authentication
            username = self.authenticate(sock, client_rsa)
            if not username:
                return
                
            # Message handling
            while True:
                encrypted = sock.recv(4096)
                if not encrypted:
                    break
                
                msg = client_rsa.decrypt_message(encrypted)
                if msg.startswith('EXIT'):
                    break
                self.handle_message(username, msg, sock, client_rsa)
                
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            if username in self.clients:
                del self.clients[username]
            sock.close()

    def authenticate(self, sock: socket.socket, rsa: RSA_encryptor) -> str:
        while True:
            encrypted = sock.recv(4096)
            if not encrypted:
                return ""
                
            try:
                msg = self.server_rsa.decrypt_message(encrypted)
                
                if msg.startswith("REGISTER"):
                    _, user, pwd_hash, salt = msg.split(maxsplit=3)
                    if self.db.register_user(user, pwd_hash, bytes.fromhex(salt)):
                        sock.send(rsa.encrypt_message("REGISTER_SUCCESS"))
                        self.clients[user] = {'socket': sock, 'rsa': rsa}
                        return user

                elif msg.startswith("GET_SALT"):
                    _, username = msg.split(maxsplit=1)
                    salt = self.db_handler.get_salt(username)  # Implement this in DatabaseHandler
                    sock.send(rsa.encrypt_message(salt.hex()))

                elif msg.startswith("LOGIN"):
                    _, user, pwd_hash = msg.split(maxsplit=2)
                    if self.db.verify_user(user, pwd_hash):
                        sock.send(rsa.encrypt_message("LOGIN_SUCCESS"))
                        self.clients[user] = {'socket': sock, 'rsa': rsa}
                        return user
                        
                sock.send(rsa.encrypt_message("AUTH_FAILED"))
            except:
                sock.send(rsa.encrypt_message("INVALID_REQUEST"))

    def handle_message(self, sender: str, msg: str, sock: socket.socket, rsa: RSA_encryptor):
        if msg.startswith("@"):  # Format: "@username message"
            target, _, message = msg[1:].partition(' ')
            if target in self.clients:
                target_data = self.clients[target]
                encrypted = target_data['rsa'].encrypt_message(f"@{sender}: {message}")
                target_data['socket'].send(encrypted)
            else:
                sock.send(rsa.encrypt_message(f"NOTFOUND User {target} not found"))
        elif msg == "LIST":  # List online users
            online_users = [u for u in self.clients if u != sender]
            response = "ONLINE: " + ", ".join(online_users) if online_users else "No other users" 

if __name__ == "__main__":
    server = Server('localhost', 12345)