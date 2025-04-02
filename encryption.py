from rsa.key import newkeys
import rsa

class encryption():
    def __init__(self, key_size=1024):
        self.public_key, self.private_key = newkeys(key_size)
        self.peer_public_key = None

    def generate_keys(self):
        self.public_key, self.private_key = rsa.newkeys(1024)

    def encrypt_message(self, message):
        if not self.peer_public_key:
            raise ValueError("Peer public key is not set.")
        return rsa.encrypt(message.encode('utf-8'), self.peer_public_key)
    
    def decrypt_message(self, encrypted_message):
        try:
            return rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')
        except rsa.DecryptionError:
            return "Decryption failed."
        
    def get_public_key(self) -> bytes:
        return self.public_key.save_pkcs1()
    
    def set_public_key(self, public_key: bytes):
        self.peer_public_key = rsa.PublicKey.load_pkcs1(public_key)