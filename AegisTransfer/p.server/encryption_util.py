from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class EncryptionManager:
    def __init__(self, rsa_mode=False):
        self.rsa_mode = rsa_mode
        self.base_dir = Path(__file__).parent.absolute()
        
        if rsa_mode:
            try:
                self.private_key = self._load_private_key()
                logger.info("RSA mode initialized with private key")
            except Exception as e:
                logger.error(f"Failed to load RSA private key: {e}")
                raise

    def _load_private_key(self):
        """Load and validate private key with strict permissions"""
        key_path = self.base_dir / "server_private.pem"
        if not key_path.exists():
            raise FileNotFoundError(f"Private key not found at {key_path}")
            
        current_mode = os.stat(key_path).st_mode & 0o777
        if current_mode != 0o600:
            try:
                os.chmod(key_path, 0o600)
                logger.info(f"Fixed key permissions (was {oct(current_mode)}, now 0o600)")
            except Exception as e:
                raise PermissionError(f"Failed to set key permissions: {e}")
            
        with open(key_path, "rb") as key_file:
            try:
                key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                if not isinstance(key, rsa.RSAPrivateKey):
                    raise ValueError("Not an RSA private key")
                return key
            except Exception as e:
                raise ValueError(f"Invalid private key: {e}")

    def _decrypt_key(self, encrypted_key):
        """Decrypt RSA encrypted key to get AES key"""
        try:
            # RSA ile şifrelenmiş anahtarı çöz
            key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if len(key) != 32:
                raise ValueError(f"Decrypted key length invalid: {len(key)} bytes, expected 32")
            return key
        except Exception as e:
            raise ValueError(f"Key decryption failed: {e}")

    def decrypt_file(self, encrypted_file_path, encrypted_key=None):
        """Decrypt a file using AES-GCM with RSA encrypted key"""
        try:
            encrypted_file_path = str(Path(encrypted_file_path).absolute())
            logger.info(f"Decrypting: {encrypted_file_path}")

            if not Path(encrypted_file_path).exists():
                raise FileNotFoundError(f"File not found: {encrypted_file_path}")

            file_size = os.path.getsize(encrypted_file_path)
            if file_size < 32:
                raise ValueError(f"File too small ({file_size} bytes), expected at least 32 bytes")

            with open(encrypted_file_path, "rb") as file:
                iv = file.read(16)
                tag = file.read(16)
                ciphertext = file.read()

            logger.debug(f"IV: {iv.hex()}")
            logger.debug(f"Tag: {tag.hex()}")
            logger.debug(f"Ciphertext length: {len(ciphertext)} bytes")

            if encrypted_key is None:
                raise ValueError("No encryption key provided")
                
            # RSA modunda ise anahtarı önce çöz
            if self.rsa_mode:
                key = self._decrypt_key(encrypted_key)
                logger.debug(f"Using decrypted AES key: {key.hex()[:8]}... (length: {len(key)} bytes)")
            else:
                raise RuntimeError("Direct key decryption requires RSA mode")

            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            logger.info("Decryption successful")
            return decrypted

        except Exception as e:
            error_msg = (
                f"Failed to decrypt {encrypted_file_path}\n"
                f"Key used: {encrypted_key[:8].hex()}... (len: {len(encrypted_key)})\n"
                f"Error: {type(e).__name__}: {str(e)}"
            )
            logger.error(error_msg)
            raise ValueError(error_msg)
