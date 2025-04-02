from rsa.key import newkeys
import rsa

import hmac
import hashlib
import os

class HMAC_encryptor():
    # Create HMAC-SHA256 hash ith optional secret key
    def __init__(self, secret_key=None):
        self.secret_key = secret_key if secret_key else os.urandom(32)

    # Create HMAC-SHA256 hash of a message
    def create_hash(self, message, salt=None):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if salt:
            message = salt + message
            
        return hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()

    # Verify if HMAC matches expected value
    def verify_hash(self, message, received_hash, salt=None):
        expected_hash = self.create_hash(message, salt)
        return hmac.compare_digest(expected_hash, received_hash)

    # Generate a random 16-byte salt
    @staticmethod
    def generate_salt():
        return os.urandom(16)

class RSA_encryptor():
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