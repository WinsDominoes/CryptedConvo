# HMAC.py
import hmac
import hashlib

# Create HMAC-SHA256 hash
def create_hmac(key, message):
    if isinstance(message, str):
        message = message.encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()

# Verify HMAC mals
# tches
def verify_hmac(key, message, received_hmac):
    expected_hmac = create_hmac(key, message)
    return hmac.compare_digest(expected_hmac, received_hmac)