import paramiko
import os
import time
import logging
from dotenv import load_dotenv
from typing import Optional, Tuple

load_dotenv()

class SecureTransfer:
    def __init__(self):
        """
        Secure file transfer class with enhanced security and reliability
        Gelişmiş güvenlik ve güvenilirlik özelliklerine sahip güvenli dosya transfer sınıfı
        
        Features/Özellikler:
        - SSH connection with strong encryption algorithms
          Güçlü şifreleme algoritmaları ile SSH bağlantısı
        - Automatic reconnection and retry mechanism
          Otomatik yeniden bağlantı ve yeniden deneme mekanizması
        - File verification and integrity checks
          Dosya doğrulama ve bütünlük kontrolleri
        - Comprehensive logging
          Kapsamlı log kaydı
        """
        self.ssh: Optional[paramiko.SSHClient] = None  # Initialize as None for clean restart / Yeniden başlatmak için None olarak başlat
        self._initialize_ssh()
        logging.basicConfig(
            filename='secure_transfer.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def _initialize_ssh(self) -> None:
        """Initialize a new SSH client / Yeni bir SSH istemcisi oluştur"""
        if self.ssh is not None:
            self.ssh.close()
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    def connect(self) -> bool:
        """
        Establish secure SSH connection / Güvenli SSH bağlantısı kur
        
        Returns:
            bool: True if connection successful, raises exception otherwise
                  Bağlantı başarılıysa True, aksi halde exception fırlatır
                  
        Raises:
            paramiko.SSHException: For SSH-specific errors / SSH'a özel hatalar
            Exception: For other connection errors / Diğer bağlantı hataları
        """
        try:
            if self.is_connected():
                return True
                
            self._initialize_ssh()  # Clean start for reconnection / Yeniden bağlantı için temiz başlangıç
            
            # Secure encryption algorithms / Güvenli şifreleme algoritmaları
            self.ssh.connect(
                hostname=os.getenv("SSH_HOST"),
                username=os.getenv("SSH_USER"),
                password=os.getenv("SSH_PASS"),
                allow_agent=False,
                look_for_keys=False,
                timeout=15,  # Increased timeout / Zaman aşımını artırdık
                disabled_algorithms={
                    'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512'],
                    'keys': ['ssh-rsa']
                }
            )
            
            # Transport layer security settings / Transport katmanı güvenlik ayarları
            transport = self.ssh.get_transport()
            if transport:
                transport.set_ciphers('aes256-gcm@openssh.com,chacha20-poly1305@openssh.com')
                transport.set_kex('curve25519-sha256,diffie-hellman-group-exchange-sha256')
                transport.set_mac('hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com')
                transport.use_compression(False)  # Disable compression / Sıkıştırmayı kapat
            
            logging.info("SSH connection established successfully / SSH bağlantısı başarıyla kuruldu")
            print("✅ SSH connection successful! / SSH bağlantısı başarılı!")
            return True
            
        except paramiko.SSHException as e:
            logging.error(f"SSH Error: {str(e)} / SSH Hatası: {str(e)}")
            print(f"🔴 SSH Error: {str(e)} / SSH Hatası: {str(e)}")
            self._initialize_ssh()  # Clean up on error / Hata durumunda temizle
            raise
        except Exception as e:
            logging.error(f"General Error: {str(e)} / Genel Hata: {str(e)}")
            print(f"🔴 General Error: {str(e)} / Genel Hata: {str(e)}")
            self._initialize_ssh()  # Clean up on error / Hata durumunda temizle
            raise

    def is_connected(self) -> bool:
        """
        Check if connection is active / Bağlantının aktif olup olmadığını kontrol eder
        
        Returns:
            bool: True if connected and active, False otherwise
                  Bağlantı aktifse True, değilse False
        """
        if self.ssh is None:
            return False
        transport = self.ssh.get_transport()
        return transport is not None and transport.is_active()

    def transfer_file(self, local_path: str, remote_path: str, retries: int = 3) -> bool:
        """
        Secure file transfer with verification / Doğrulamalı güvenli dosya transferi
        
        Args:
            local_path: Path to local file / Yerel dosya yolu
            remote_path: Destination path on remote server / Uzak sunucudaki hedef yol
            retries: Number of retry attempts / Yeniden deneme sayısı
            
        Returns:
            bool: True if transfer successful, False otherwise
                  Transfer başarılıysa True, değilse False
        """
        for attempt in range(retries):
            try:
                if not self.is_connected():
                    self.connect()

                # Verify local file exists / Yerel dosya varlığını kontrol et
                if not os.path.exists(local_path):
                    error_msg = f"Local file not found: {local_path} / Yerel dosya bulunamadı: {local_path}"
                    logging.error(error_msg)
                    print(f"🔴 {error_msg}")
                    return False

                local_size = os.path.getsize(local_path)
                start_time = time.time()

                with self.ssh.open_sftp() as sftp:
                    # File transfer / Dosya transferi
                    sftp.put(local_path, remote_path)
                    
                    # Verification / Doğrulama
                    remote_size = sftp.stat(remote_path).st_size
                    elapsed_time = time.time() - start_time
                    transfer_speed = (local_size / (1024 * 1024)) / elapsed_time  # MB/s

                    if local_size == remote_size:
                        success_msg = (f"{local_path} → {remote_path} transferred successfully. "
                                     f"Size: {local_size/1024:.2f} KB, Time: {elapsed_time:.2f}s, "
                                     f"Speed: {transfer_speed:.2f} MB/s\n"
                                     f"{local_path} → {remote_path} başarıyla transfer edildi. "
                                     f"Boyut: {local_size/1024:.2f} KB, Süre: {elapsed_time:.2f}s, "
                                     f"Hız: {transfer_speed:.2f} MB/s")
                        logging.info(success_msg)
                        print(f"🟢 {success_msg}")
                        return True
                    else:
                        error_msg = (f"Size mismatch: Local={local_size} bytes, "
                                   f"Remote={remote_size} bytes\n"
                                   f"Boyut uyuşmazlığı: Yerel={local_size} bytes, "
                                   f"Uzak={remote_size} bytes")
                        logging.error(error_msg)
                        print(f"🔴 {error_msg}")
                        return False

            except PermissionError:
                error_msg = f"Permission denied: {remote_path} is not writable / İzin hatası: {remote_path} yazılabilir değil"
                logging.error(error_msg)
                print(f"🔴 {error_msg}")
                return False
            except FileNotFoundError:
                error_msg = f"Remote directory not found: {os.path.dirname(remote_path)} / Uzak dizin bulunamadı: {os.path.dirname(remote_path)}"
                logging.error(error_msg)
                print(f"🔴 {error_msg}")
                return False
            except Exception as e:
                if attempt == retries - 1:
                    error_msg = (f"Transfer failed after {retries} attempts: "
                               f"{type(e).__name__} - {str(e)}\n"
                               f"Transfer {retries} kez başarısız oldu: "
                               f"{type(e).__name__} - {str(e)}")
                    logging.error(error_msg)
                    print(f"🔴 {error_msg}")
                    return False
                
                logging.warning(f"Attempt {attempt + 1}/{retries} failed. Retrying... / Deneme {attempt + 1}/{retries} başarısız. Yeniden deniyor...")
                print(f"🔄 Retrying ({attempt + 1}/{retries})... / Yeniden deniyor ({attempt + 1}/{retries})...")
                time.sleep(2)
                self.connect()

    def close(self) -> None:
        """Close connection securely / Bağlantıyı güvenli şekilde kapat"""
        try:
            if self.is_connected():
                self.ssh.close()
                logging.info("SSH connection closed successfully / SSH bağlantısı başarıyla kapatıldı")
                print("✅ SSH connection closed / SSH bağlantısı kapatıldı")
        except Exception as e:
            logging.error(f"Error closing connection: {str(e)} / Bağlantı kapatılırken hata: {str(e)}")
            print(f"🔴 Error closing connection: {str(e)} / Bağlantı kapatılırken hata: {str(e)}")

    def __enter__(self):
        """Context manager support / Context manager desteği"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support / Context manager desteği"""
        self.close()