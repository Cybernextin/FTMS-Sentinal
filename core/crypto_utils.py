import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import config

class CryptoManager:
    """
    Handles encryption and decryption using pycryptodome (AES-GCM).
    More portable for environments where cryptography fails to build.
    """
    def __init__(self):
        # We use the config key. If it's a Fernet key (32 bytes base64), we decode it.
        try:
            self.key = base64.urlsafe_b64decode(config.ENCRYPTION_KEY)
            if len(self.key) != 32:
                # If not 32 bytes, derive a 32-byte key
                self.key = PBKDF2(config.ENCRYPTION_KEY, b'salt_', dkLen=32)
        except Exception:
            self.key = PBKDF2(config.ENCRYPTION_KEY, b'salt_', dkLen=32)

    def encrypt_data(self, data):
        """Encrypts string or bytes data using AES-GCM."""
        if isinstance(data, str):
            data = data.encode()
        
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # We store nonce + tag + ciphertext
        result = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
        return result

    def decrypt_data(self, encrypted_data):
        """Decrypts AES-GCM encrypted data."""
        try:
            raw_data = base64.b64decode(encrypted_data)
            nonce = raw_data[:16]
            tag = raw_data[16:32]
            ciphertext = raw_data[32:]
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode()
        except Exception as e:
            return f"Error Decrypting: {str(e)}"

    def encrypt_file(self, file_path):
        """Encrypts a file in place."""
        if not os.path.exists(file_path):
            return False
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt_data(data)
        with open(file_path, 'w') as f:
            f.write(encrypted)
        return True

    def decrypt_file(self, file_path):
        """Decrypts a file in place."""
        if not os.path.exists(file_path):
            return False
        with open(file_path, 'r') as f:
            encrypted_data = f.read()
        
        try:
            decrypted = self.decrypt_data(encrypted_data)
            if decrypted.startswith("Error Decrypting:"):
                return False
                
            with open(file_path, 'wb') as f:
                f.write(decrypted.encode() if isinstance(decrypted, str) else decrypted)
            return True
        except Exception:
            return False

# Global instance for easy access
crypto_manager = CryptoManager()
