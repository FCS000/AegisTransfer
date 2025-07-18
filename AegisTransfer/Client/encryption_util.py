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
        Encryption/Decryption manager with AES-GCM and optional RSA key wrapping
        Şifreleme/Çözme yöneticisi (AES-GCM ve opsiyonel RSA anahtar sarma)
        
        Args:
            key: AES key (32 bytes) or None (auto-generates)
                   AES anahtarı (32 byte) veya None (otomatik oluşturur)
            rsa_mode: Enable RSA key wrapping mode?
                      RSA anahtar sarma modu aktif mi?
            public_key_path: Path to RSA public key
                            RSA public key dosya yolu
        """
        self.rsa_mode = rsa_mode
        self.base_dir = Path(__file__).parent.absolute()
        
        # Load public key for RSA mode
        # RSA modu için public key yükle
        if rsa_mode:
            if not public_key_path:
                public_key_path = str(self.base_dir / "server_public.pem")
            self.public_key = self._load_public_key(public_key_path)
        
        # Set AES key
        # AES anahtarını ayarla
        if key:
            if len(key) != 32:
                raise ValueError("AES key must be 32 bytes/AES anahtarı 32 byte olmalıdır")
            self.key = key
        else:
            self.key = os.urandom(32)  # 32-byte random key/32-byte rastgele anahtar
        
        # Generate IV (Initialization Vector)
        # IV (Başlatma Vektörü) oluştur
        self.iv = os.urandom(16)  # 16-byte IV for GCM/GCM için 16 byte IV

    def _load_public_key(self, path: str):
        """Load RSA public key/RSA public key yükle"""
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def _load_private_key(self, path: str):
        """Load RSA private key/RSA private key yükle"""
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

    def encrypt_file(self, input_path: str) -> Tuple[str, Optional[bytes]]:
        """
        Encrypts file and returns encrypted file path
        Dosyayı şifreler ve şifrelenmiş dosya yolunu döndürür
        
        Returns:
            RSA mode: (encrypted_file_path, encrypted_key) tuple
                      (şifrelenmiş_dosya_yolu, şifrelenmiş_anahtar) ikilisi
            Normal mode: encrypted_file_path
                         şifrelenmiş_dosya_yolu
        """
        try:
            # Read file
            # Dosyayı oku
            with open(input_path, "rb") as file:
                plaintext = file.read()

            # Encryption process
            # Şifreleme işlemi
            if self.rsa_mode:
                # Encrypt AES key with RSA
                # AES anahtarını RSA ile şifrele
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

            # Encrypt with AES-GCM
            # AES-GCM ile şifrele
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(self.iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Prepare output file
            # Çıktı dosyasını hazırla
            output_path = input_path + ".enc"
            with open(output_path, "wb") as file:
                file.write(self.iv)
                file.write(encryptor.tag)
                file.write(ciphertext)

            return (output_path, encrypted_key) if self.rsa_mode else output_path

        except Exception as e:
            raise ValueError(f"Encryption error/Şifreleme hatası: {str(e)}")

    def decrypt_file(self, input_path: str, encrypted_key: Optional[bytes] = None, private_key_path: Optional[str] = None) -> bytes:
        """
        Decrypts encrypted file
        Şifrelenmiş dosyayı çözer
        
        Args:
            input_path: Encrypted file path
                        Şifrelenmiş dosya yolu
            encrypted_key: RSA encrypted key (for RSA mode)
                          RSA ile şifrelenmiş anahtar (RSA modu için)
            private_key_path: RSA private key path (for RSA mode)
                             RSA private key dosya yolu (RSA modu için)
        Returns:
            Decrypted data (bytes)
            Çözülmüş veri (bytes)
        """
        try:
            # Read encrypted file (IV + Tag + Ciphertext)
            # Şifrelenmiş dosyayı oku (IV + Tag + ŞifreliMetin)
            with open(input_path, "rb") as file:
                iv = file.read(16)
                tag = file.read(16)
                ciphertext = file.read()

            # Determine key
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

            # Decrypt with AES-GCM
            # AES-GCM ile çöz
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        except Exception as e:
            raise ValueError(f"Decryption error/Çözme hatası: {str(e)}")

    def save_key(self, key_path: str = "encryption_key.bin"):
        """Saves AES key to file/AES anahtarını dosyaya kaydeder"""
        with open(key_path, "wb") as f:
            f.write(self.key)

    @staticmethod
    def generate_key_pair(private_path: str = "server_private.pem", public_path: str = "server_public.pem"):
        """
        Generates RSA key pair
        RSA anahtar çifti oluşturur
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Save private key
        # Private key'i kaydet
        with open(private_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(private_path, 0o600)  # Only owner can read/write/Sadece sahibi okuyabilir/yazabilir

        # Save public key
        # Public key'i kaydet
        with open(public_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))