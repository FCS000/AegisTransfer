# encryption_util.py (Güncellenmiş ve Uyumlu Sürüm)
"""
Gelişmiş Dosya Şifreleme Modülü - RSA ve AES-GCM Desteği
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import base64
from typing import Tuple, Optional
from pathlib import Path

class EncryptionManager:
    def __init__(self, key: Optional[bytes] = None, rsa_mode: bool = False, public_key_path: Optional[str] = None):
        """
        Args:
            key: AES anahtarı (32 byte) veya None (otomatik oluşturur)
            rsa_mode: RSA şifreleme aktif mi?
            public_key_path: RSA public key dosya yolu
        """
        self.rsa_mode = rsa_mode
        self.base_dir = Path(__file__).parent.absolute()
        
        # RSA modu için public key yükle
        if rsa_mode:
            if not public_key_path:
                public_key_path = str(self.base_dir / "server_public.pem")
            self.public_key = self._load_public_key(public_key_path)
        
        # AES anahtarını ayarla
        if key:
            if len(key) != 32:
                raise ValueError("AES anahtarı 32 byte olmalıdır")
            self.key = key
        else:
            self.key = os.urandom(32)  # 32-byte rastgele anahtar
        
        # IV (Initialization Vector) oluştur
        self.iv = os.urandom(16)  # GCM için 16 byte IV

    def _load_public_key(self, path: str):
        """RSA public key yükle"""
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def _load_private_key(self, path: str):
        """RSA private key yükle"""
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

    def encrypt_file(self, input_path: str) -> Tuple[str, Optional[bytes]]:
        """
        Dosyayı şifreler ve şifrelenmiş dosya yolunu döndürür
        RSA modunda: (encrypted_file_path, encrypted_key) tuple döner
        Normal modda: encrypted_file_path döner
        """
        try:
            # Dosyayı oku
            with open(input_path, "rb") as file:
                plaintext = file.read()

            # Şifreleme işlemi
            if self.rsa_mode:
                # RSA ile AES anahtarını şifrele
                encrypted_key = self.public_key.encrypt(
                    self.key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                encrypted_key = None

            # AES-GCM ile şifrele
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(self.iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Çıktı dosyasını hazırla
            output_path = input_path + ".enc"
            with open(output_path, "wb") as file:
                file.write(self.iv)
                file.write(encryptor.tag)
                file.write(ciphertext)

            return (output_path, encrypted_key) if self.rsa_mode else output_path

        except Exception as e:
            raise ValueError(f"Şifreleme hatası: {str(e)}")

    def decrypt_file(self, input_path: str, encrypted_key: Optional[bytes] = None, private_key_path: Optional[str] = None) -> bytes:
        """
        Şifrelenmiş dosyayı çözer
        Args:
            input_path: Şifrelenmiş dosya yolu
            encrypted_key: RSA ile şifrelenmiş anahtar (RSA modu için)
            private_key_path: RSA private key dosya yolu (RSA modu için)
        Returns:
            Çözülmüş veri (bytes)
        """
        try:
            # Şifrelenmiş dosyayı oku (IV + Tag + Ciphertext)
            with open(input_path, "rb") as file:
                iv = file.read(16)
                tag = file.read(16)
                ciphertext = file.read()

            # Anahtar belirleme
            if encrypted_key is not None and private_key_path:
                private_key = self._load_private_key(private_key_path)
                key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                key = self.key

            # AES-GCM ile çöz
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        except Exception as e:
            raise ValueError(f"Çözme hatası: {str(e)}")

    def save_key(self, key_path: str = "encryption_key.bin"):
        """AES anahtarını dosyaya kaydeder"""
        with open(key_path, "wb") as f:
            f.write(self.key)

    @staticmethod
    def generate_key_pair(private_path: str = "server_private.pem", public_path: str = "server_public.pem"):
        """RSA anahtar çifti oluşturur"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Private key'i kaydet
        with open(private_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(private_path, 0o600)  # Sadece sahibi okuyabilir/yazabilir

        # Public key'i kaydet
        with open(public_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))