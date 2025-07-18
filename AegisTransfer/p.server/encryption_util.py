from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import logging
from pathlib import Path
from typing import Optional, Union, Tuple

logger = logging.getLogger(__name__)

class EncryptionManager:
    def __init__(self, rsa_mode: bool = False):
        """
        Encryption/Decryption manager with RSA and AES-GCM support
        RSA ve AES-GCM destekli Şifreleme/Şifre Çözme yöneticisi
        
        Args:
            rsa_mode: Whether to enable RSA key wrapping (default: False)
                     RSA anahtar sarmalama modu (varsayılan: False)
                     
        Raises:
            FileNotFoundError: If private key not found when RSA mode enabled
                              RSA modu açıkken private key bulunamazsa
            PermissionError: If key file permissions are insecure
                            Key dosyası izinleri güvensizse
            ValueError: If key is invalid
                       Key geçersizse
        """
        self.rsa_mode = rsa_mode
        self.base_dir = Path(__file__).parent.absolute()
        
        if rsa_mode:
            try:
                self.private_key = self._load_private_key()
                logger.info("RSA mode initialized with private key / RSA modu private key ile başlatıldı")
            except Exception as e:
                logger.error(f"Failed to load RSA private key / RSA private key yüklenemedi: {e}")
                raise

    def _load_private_key(self) -> rsa.RSAPrivateKey:
        """
        Load and validate private key with strict permissions
        Private key'i sıkı izin kontrolleriyle yükle ve doğrula
        
        Returns:
            RSAPrivateKey: Validated private key
                           Doğrulanmış private key
            
        Raises:
            FileNotFoundError: If key file doesn't exist
                              Key dosyası yoksa
            PermissionError: If key permissions are too open
                            Key izinleri çok açıksa
            ValueError: If key is invalid or not RSA
                       Key geçersiz veya RSA değilse
        """
        key_path = self.base_dir / "server_private.pem"
        if not key_path.exists():
            raise FileNotFoundError(f"Private key not found at {key_path} / Private key bulunamadı: {key_path}")
            
        # Strict permission check (600 or more restrictive)
        # Sıkı izin kontrolü (600 veya daha kısıtlayıcı)
        current_mode = os.stat(key_path).st_mode & 0o777
        if current_mode != 0o600:
            try:
                os.chmod(key_path, 0o600)
                logger.info(f"Fixed key permissions (was {oct(current_mode)}, now 0o600) / Key izinleri düzeltildi (eski {oct(current_mode)}, yeni 0o600)")
            except Exception as e:
                raise PermissionError(f"Failed to set key permissions / Key izinleri ayarlanamadı: {e}")
            
        with open(key_path, "rb") as key_file:
            try:
                key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                if not isinstance(key, rsa.RSAPrivateKey):
                    raise ValueError("Not an RSA private key / RSA private key değil")
                return key
            except Exception as e:
                raise ValueError(f"Invalid private key / Geçersiz private key: {e}")

    def _decrypt_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt RSA encrypted key to get AES key
        RSA ile şifrelenmiş anahtarı çözerek AES anahtarı elde et
        
        Args:
            encrypted_key: RSA encrypted AES key (256 bits)
                           RSA ile şifrelenmiş AES anahtarı (256 bit)
                           
        Returns:
            bytes: Decrypted AES key (32 bytes)
                   Çözülmüş AES anahtarı (32 byte)
                   
        Raises:
            ValueError: If decryption fails or key length invalid
                       Şifre çözme başarısız veya anahtar uzunluğu geçersizse
        """
        try:
            # Decrypt with RSA-OAEP-SHA256
            # RSA-OAEP-SHA256 ile şifre çöz
            key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if len(key) != 32:
                raise ValueError(f"Decrypted key length invalid: {len(key)} bytes, expected 32 / Çözülmüş anahtar uzunluğu geçersiz: {len(key)} byte, beklenen 32")
            return key
        except Exception as e:
            raise ValueError(f"Key decryption failed / Anahtar şifre çözme başarısız: {e}")

    def decrypt_file(self, encrypted_file_path: Union[str, Path], encrypted_key: Optional[bytes] = None) -> bytes:
        """
        Decrypt a file using AES-GCM with optional RSA key wrapping
        AES-GCM ile dosya şifresini çöz (opsiyonel RSA anahtar sarmalama)
        
        Args:
            encrypted_file_path: Path to encrypted file
                                Şifrelenmiş dosya yolu
            encrypted_key: RSA encrypted AES key (required in RSA mode)
                          RSA ile şifrelenmiş AES anahtarı (RSA modunda gerekli)
                          
        Returns:
            bytes: Decrypted file contents
                   Çözülmüş dosya içeriği
                   
        Raises:
            FileNotFoundError: If file doesn't exist
                              Dosya bulunamazsa
            ValueError: For various decryption failures
                       Çeşitli şifre çözme hataları için
        """
        try:
            encrypted_file_path = str(Path(encrypted_file_path).absolute())
            logger.info(f"Decrypting: {encrypted_file_path} / Şifre çözülüyor: {encrypted_file_path}")

            if not Path(encrypted_file_path).exists():
                raise FileNotFoundError(f"File not found: {encrypted_file_path} / Dosya bulunamadı: {encrypted_file_path}")

            file_size = os.path.getsize(encrypted_file_path)
            if file_size < 32:  # IV (16) + Tag (16) minimum
                raise ValueError(f"File too small ({file_size} bytes), expected at least 32 bytes / Dosya çok küçük ({file_size} byte), en az 32 byte bekleniyor")

            with open(encrypted_file_path, "rb") as file:
                iv = file.read(16)
                tag = file.read(16)
                ciphertext = file.read()

            logger.debug(f"IV: {iv.hex()}")
            logger.debug(f"Tag: {tag.hex()}")
            logger.debug(f"Ciphertext length: {len(ciphertext)} bytes / Şifreli metin uzunluğu: {len(ciphertext)} bayt")

            if encrypted_key is None:
                raise ValueError("No encryption key provided / Şifreleme anahtarı sağlanmadı")
                
            # In RSA mode, first decrypt the AES key
            # RSA modunda önce AES anahtarını çöz
            if self.rsa_mode:
                key = self._decrypt_key(encrypted_key)
                logger.debug(f"Using decrypted AES key: {key.hex()[:8]}... (length: {len(key)} bytes) / Çözülmüş AES anahtarı kullanılıyor: {key.hex()[:8]}... (uzunluk: {len(key)} bayt)")
            else:
                raise RuntimeError("Direct key decryption requires RSA mode / Doğrudan anahtar şifre çözme RSA modu gerektirir")

            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            logger.info("Decryption successful / Şifre çözme başarılı")
            return decrypted

        except Exception as e:
            error_msg = (
                f"Failed to decrypt {encrypted_file_path}\n"
                f"Key used: {encrypted_key[:8].hex() if encrypted_key else 'None'}... (len: {len(encrypted_key) if encrypted_key else 0})\n"
                f"Error: {type(e).__name__}: {str(e)}\n"
                f"Şifre çözme başarısız: {encrypted_file_path}\n"
                f"Kullanılan anahtar: {encrypted_key[:8].hex() if encrypted_key else 'None'}... (uzunluk: {len(encrypted_key) if encrypted_key else 0})\n"
                f"Hata: {type(e).__name__}: {str(e)}"
            )
            logger.error(error_msg)
            raise ValueError(error_msg)