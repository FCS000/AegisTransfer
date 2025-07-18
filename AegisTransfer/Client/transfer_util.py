import paramiko
import os
import time
import logging
from dotenv import load_dotenv

load_dotenv()

class SecureTransfer:
    def __init__(self):
        self.ssh = None  # Bağlantıyı yeniden başlatabilmek için None olarak başlat
        self._initialize_ssh()
        logging.basicConfig(
            filename='secure_transfer.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def _initialize_ssh(self):
        """Yeni bir SSH istemcisi oluştur"""
        if self.ssh is not None:
            self.ssh.close()
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    def connect(self):
        try:
            if self.is_connected():
                return True
                
            self._initialize_ssh()  # Yeniden bağlantı için temiz başlangıç
            
            # Güvenli şifreleme algoritmaları
            self.ssh.connect(
                hostname=os.getenv("SSH_HOST"),
                username=os.getenv("SSH_USER"),
                password=os.getenv("SSH_PASS"),
                allow_agent=False,
                look_for_keys=False,
                timeout=15,  # Zaman aşımını artırdık
                disabled_algorithms={
                    'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512'],
                    'keys': ['ssh-rsa']
                }
            )
            
            # Transport katmanı güvenlik ayarları
            transport = self.ssh.get_transport()
            if transport:
                transport.set_ciphers('aes256-gcm@openssh.com,chacha20-poly1305@openssh.com')
                transport.set_kex('curve25519-sha256,diffie-hellman-group-exchange-sha256')
                transport.set_mac('hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com')
                transport.use_compression(False)  # Sıkıştırmayı kapat
            
            logging.info("SSH bağlantısı başarıyla kuruldu")
            print("✅ SSH bağlantısı başarılı!")
            return True
            
        except paramiko.SSHException as e:
            logging.error(f"SSH Hatası: {str(e)}")
            print(f"🔴 SSH Hatası: {str(e)}")
            self._initialize_ssh()  # Hata durumunda temizle
            raise
        except Exception as e:
            logging.error(f"Genel Hata: {str(e)}")
            print(f"🔴 Genel Hata: {str(e)}")
            self._initialize_ssh()  # Hata durumunda temizle
            raise

    def is_connected(self):
        """Bağlantının aktif olup olmadığını kontrol eder"""
        transport = self.ssh.get_transport()
        return transport is not None and transport.is_active()

    def transfer_file(self, local_path, remote_path, retries=3):
        """Dosya transferi için geliştirilmiş metod"""
        for attempt in range(retries):
            try:
                if not self.is_connected():
                    self.connect()

                # Dosya varlığını kontrol et
                if not os.path.exists(local_path):
                    error_msg = f"Yerel dosya bulunamadı: {local_path}"
                    logging.error(error_msg)
                    print(f"🔴 {error_msg}")
                    return False

                local_size = os.path.getsize(local_path)
                start_time = time.time()

                with self.ssh.open_sftp() as sftp:
                    # Dosya transferi
                    sftp.put(local_path, remote_path)
                    
                    # Doğrulama
                    remote_size = sftp.stat(remote_path).st_size
                    elapsed_time = time.time() - start_time
                    transfer_speed = (local_size / (1024 * 1024)) / elapsed_time  # MB/s

                    if local_size == remote_size:
                        success_msg = (f"{local_path} → {remote_path} başarıyla transfer edildi. "
                                     f"Boyut: {local_size/1024:.2f} KB, Süre: {elapsed_time:.2f}s, "
                                     f"Hız: {transfer_speed:.2f} MB/s")
                        logging.info(success_msg)
                        print(f"🟢 {success_msg}")
                        return True
                    else:
                        error_msg = (f"Boyut uyuşmazlığı: Yerel={local_size} bytes, "
                                   f"Uzak={remote_size} bytes")
                        logging.error(error_msg)
                        print(f"🔴 {error_msg}")
                        return False

            except PermissionError:
                error_msg = f"İzin hatası: {remote_path} yazılabilir değil"
                logging.error(error_msg)
                print(f"🔴 {error_msg}")
                return False
            except FileNotFoundError:
                error_msg = f"Uzak dizin bulunamadı: {os.path.dirname(remote_path)}"
                logging.error(error_msg)
                print(f"🔴 {error_msg}")
                return False
            except Exception as e:
                if attempt == retries - 1:
                    error_msg = f"Transfer {retries} kez başarısız oldu: {type(e).__name__} - {str(e)}"
                    logging.error(error_msg)
                    print(f"🔴 {error_msg}")
                    return False
                
                logging.warning(f"Deneme {attempt + 1}/{retries} başarısız. Yeniden deniyor...")
                print(f"🔄 Yeniden deniyor ({attempt + 1}/{retries})...")
                time.sleep(2)
                self.connect()

    def close(self):
        """Bağlantıyı güvenli şekilde kapat"""
        try:
            if self.is_connected():
                self.ssh.close()
                logging.info("SSH bağlantısı başarıyla kapatıldı")
                print("✅ SSH bağlantısı kapatıldı")
        except Exception as e:
            logging.error(f"Bağlantı kapatılırken hata: {str(e)}")
            print(f"🔴 Bağlantı kapatılırken hata: {str(e)}")

    def __enter__(self):
        """Context manager desteği"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager desteği"""
        self.close()