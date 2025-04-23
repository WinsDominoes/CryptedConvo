from rsa.key import newkeys
import rsa

from dotenv import load_dotenv
import shutil
import hmac
import hashlib
import os

class HMAC_encryptor:

    # Initialize with secret key from .env 
    def __init__(self):
        if not os.path.exists('.env'):
            self.generate_env_template()  # Create template
        load_dotenv()  # Load environment variables
        self.secret_key = self._load_key_from_env()
        if not self.secret_key:
            raise ValueError("No HMAC secret key found. Set HMAC_SECRET in .env or pass explicitly")

    # Load key from .env file, converting hex string to bytes if needed
    def _load_key_from_env(self):
        key_str = os.getenv('HMAC_KEY')
        if not key_str:
            return None
        
        # If key is in hex format (e.g., from os.urandom().hex())
        if len(key_str) == 64:  # 32-byte key in hex
            try:
                return bytes.fromhex(key_str)
            except ValueError:
                pass
                
        return key_str.encode('utf-8')  # Fallback to UTF-8 encoded string
    
    # Create HMAC-SHA256 hash of message with optional salt
    def create_hash(self, message, salt=None):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if salt:
            message = salt + message
            
        return hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
   
    # Verify HMAC matches expected value
    @staticmethod
    def verify_hash(received_hash, expected_hash):
        return hmac.compare_digest(received_hash, expected_hash)

    # Generate random 16-byte salt
    @staticmethod
    def generate_salt():
        return os.urandom(16)

    # Generate a .env template with random key
    @staticmethod
    def generate_env_template():
        key = os.urandom(32)
        with open('.env', 'w') as f:
            f.write(f"# HMAC Secret Key (32 bytes)\nHMAC_KEY={key.hex()}\n")
        return key
    
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
        except rsa.DecryptionError as e:
            print(f"[RSA] Decryption failed: {e}")
            return None
        
    def get_public_key(self) -> bytes:
        return self.public_key.save_pkcs1()
    
    def set_public_key(self, public_key: bytes):
        self.peer_public_key = rsa.PublicKey.load_pkcs1(public_key)