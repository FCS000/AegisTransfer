from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import sys
import paramiko
import os
import hashlib
import tempfile
import base64
import json
import glob
from datetime import datetime
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit, 
                            QProgressBar, QComboBox, QGroupBox, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# ======================== ENCRYPTION MANAGER ========================
def load_server_public_key():
    """Sunucunun public key'ini yükle"""
    try:
        with open("server_public.pem", "rb") as f:
            return load_pem_public_key(f.read())
    except Exception as e:
        print(f"Public key yükleme hatası: {str(e)}")
        return None

class EncryptionManager:
    def __init__(self, key=None):
        if key:
            self.key = base64.urlsafe_b64encode(key).decode() if isinstance(key, bytes) else key
        else:
            self.key = Fernet.generate_key().decode()
        
        self.cipher = Fernet(self.key.encode())

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.cipher.encrypt(data)
        
        # Standart isimlendirme ile geçici dosya oluştur
        temp_dir = os.path.dirname(file_path) or tempfile.gettempdir()
        temp_filename = f"enc_{os.path.basename(file_path)}.enc"
        temp_filepath = os.path.join(temp_dir, temp_filename)
        
        with open(temp_filepath, 'wb') as f:
            f.write(encrypted_data)
        
        return temp_filepath, self.key

    def save_key(self, key_path='encryption_key.key'):
        """Save encryption key to file"""
        with open(key_path, 'w') as f:
            f.write(self.key)

# ======================== SECURE TRANSFER ===========================
class SecureTransfer:
    def __init__(self):
        self.ssh = None
        self._initialize_ssh()
    
    def _initialize_ssh(self):
        if self.ssh is not None:
            self.ssh.close()
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    def connect(self, host, username, password):
        try:
            self._initialize_ssh()
            self.ssh.connect(
                hostname=host,
                username=username,
                password=password,
                timeout=15
            )
            return True
        except Exception as e:
            raise Exception(f"SSH Connection Error: {str(e)}")
    
    def transfer_file(self, local_path, remote_path, callback=None):
        try:
            with self.ssh.open_sftp() as sftp:
                sftp.put(local_path, remote_path, callback=callback)
            return True
        except Exception as e:
            raise Exception(f"Transfer Error: {str(e)}")
    
    def close(self):
        if self.ssh:
            self.ssh.close()

# ======================= TRANSFER THREAD ============================
class TransferThread(QThread):
    update_progress = pyqtSignal(int, str)
    transfer_complete = pyqtSignal(bool, str)
    log_message = pyqtSignal(str)
    key_generated = pyqtSignal(str)

    def __init__(self, local_path, remote_path, host, username, password, encrypt=False):
        super().__init__()
        self.local_path = local_path
        self.remote_path = remote_path
        self.host = host
        self.username = username
        self.password = password
        self.encrypt = encrypt
        self._is_running = True

    def run(self):
        temp_file = None
        encrypted_key = None
        try:
            # Dosya hash'ini hesapla
            file_hash = self.calculate_file_hash(self.local_path)
            self.log_message.emit(f"Dosya SHA256 Hash: {file_hash}")

            if self.encrypt:
                # Yeni EncryptionManager kullanımı
                from encryption_util import EncryptionManager
                enc_manager = EncryptionManager(rsa_mode=True)
                
                # Dosyayı şifrele (AES-GCM + RSA)
                temp_file, encrypted_key = enc_manager.encrypt_file(self.local_path)
                self.local_path = temp_file
                self.log_message.emit(f"Şifrelendi (AES-GCM): {os.path.basename(temp_file)}")
                
                # Şifrelenmiş anahtarı geçici dosyaya yaz
                encrypted_key_path = os.path.join(tempfile.gettempdir(), "enc_key.bin")
                with open(encrypted_key_path, "wb") as f:
                    f.write(encrypted_key)
                self.log_message.emit("AES anahtarı RSA ile şifrelendi (enc_key.bin)")

            # Transfer işlemleri 
            transfer = SecureTransfer()
            transfer.connect(self.host, self.username, self.password)
        
            def progress_callback(sent, total):
                percent = int((sent/total) * 100)
                self.update_progress.emit(percent, f"{sent}/{total} bayt")
        
            # Ana dosyayı transfer et
            remote_filename = os.path.basename(self.local_path)
            final_remote_path = os.path.join(self.remote_path, remote_filename)
            transfer.transfer_file(self.local_path, final_remote_path, progress_callback)
        
            # Şifrelenmiş anahtarı transfer et (varsa)
            if self.encrypt and encrypted_key:
                key_remote_path = os.path.join(self.remote_path, "enc_key.bin")
                transfer.transfer_file(encrypted_key_path, key_remote_path)
                self.log_message.emit("Şifrelenmiş anahtar transfer edildi")
        
            transfer.close()
            self.transfer_complete.emit(True, "Transfer başarıyla tamamlandı!")
        
        except Exception as e:
            self.transfer_complete.emit(False, f"Hata: {str(e)}")
        finally:
            # Geçici dosyaları temizle
            for file_path in [temp_file, encrypted_key_path if 'encrypted_key_path' in locals() else None]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        self.log_message.emit(f"Temizleme hatası: {str(e)}")
    def calculate_file_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

# ======================== MAIN GUI =================================
class SecureTransferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Güvenli Dosya Transferi v2.1")
        self.setGeometry(100, 100, 800, 600)
        self.clean_temp_files()  # Başlangıçta temizlik
        self.init_ui()
        self.transfer_thread = None

    def clean_temp_files(self):
        """Geçici dosyaları temizle"""
        temp_dir = tempfile.gettempdir()
        for pattern in ["tmp*.enc", "enc_*.enc"]:
            for file in glob.glob(os.path.join(temp_dir, pattern)):
                try:
                    os.remove(file)
                    self.log_message(f"Temizlenen geçici dosya: {os.path.basename(file)}")
                except Exception as e:
                    self.log_message(f"Temizleme hatası: {str(e)}")

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()

        # Bağlantı Ayarları
        connection_group = QGroupBox("Bağlantı Ayarları")
        connection_layout = QVBoxLayout()
        
        # Host
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("192.168.1.40")
        host_layout.addWidget(self.host_input)
        connection_layout.addLayout(host_layout)

        # Kullanıcı Adı
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Kullanıcı Adı:"))
        self.user_input = QLineEdit("ares")
        user_layout.addWidget(self.user_input)
        connection_layout.addLayout(user_layout)

        # Şifre
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Şifre:"))
        self.pass_input = QLineEdit("123")
        self.pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(self.pass_input)
        connection_layout.addLayout(pass_layout)

        connection_group.setLayout(connection_layout)
        main_layout.addWidget(connection_group)

        # Dosya Transferi
        transfer_group = QGroupBox("Dosya Transferi")
        transfer_layout = QVBoxLayout()

        # Dosya Seçimi
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Transfer edilecek dosyayı seçin...")
        file_layout.addWidget(self.file_input)
        browse_btn = QPushButton("Gözat")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        transfer_layout.addLayout(file_layout)

        # Uzak Dizin
        remote_layout = QHBoxLayout()
        remote_layout.addWidget(QLabel("Uzak Dizin:"))
        self.remote_input = QLineEdit("/home/ares/")
        remote_layout.addWidget(self.remote_input)
        transfer_layout.addLayout(remote_layout)

        # Şifreleme Seçeneği
        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Şifreleme:"))
        self.encrypt_combo = QComboBox()
        self.encrypt_combo.addItems(["Açık", "Kapalı"])
        options_layout.addWidget(self.encrypt_combo)
        
        # Anahtar Görüntüleme
        self.key_label = QLabel("Şifreleme Anahtarı")
        options_layout.addWidget(self.key_label)
        
        transfer_layout.addLayout(options_layout)

        # İlerleme Çubuğu
        self.progress_bar = QProgressBar()
        transfer_layout.addWidget(self.progress_bar)

        # Butonlar
        button_layout = QHBoxLayout()
        self.transfer_btn = QPushButton("Transferi Başlat")
        self.transfer_btn.clicked.connect(self.start_transfer)
        button_layout.addWidget(self.transfer_btn)

        self.cancel_btn = QPushButton("İptal")
        self.cancel_btn.setEnabled(False)
        button_layout.addWidget(self.cancel_btn)

        transfer_layout.addLayout(button_layout)
        transfer_group.setLayout(transfer_layout)
        main_layout.addWidget(transfer_group)

        # Log Alanı
        log_group = QGroupBox("Kayıtlar")
        log_layout = QVBoxLayout()
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        log_layout.addWidget(self.log_area)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def browse_file(self):
        """Dosya seçim diyaloğu"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Dosya Seç")
        if file_path:
            # Yol ayraçlarını standardize et
            clean_path = os.path.normpath(file_path)
            self.file_input.setText(clean_path)

    def start_transfer(self):
        local_path = self.file_input.text()
        remote_path = os.path.join(
            self.remote_input.text(),
            os.path.basename(local_path) + (".enc" if self.encrypt_combo.currentText() == "Açık" else "")
        )

        if not os.path.exists(local_path):
            QMessageBox.warning(self, "Hata", "Lütfen geçerli bir dosya seçin!")
            return

        self.transfer_thread = TransferThread(
            local_path=local_path,
            remote_path=remote_path,
            host=self.host_input.text(),
            username=self.user_input.text(),
            password=self.pass_input.text(),
            encrypt=self.encrypt_combo.currentText() == "Açık"
        )
        
        self.transfer_thread.update_progress.connect(self.update_progress)
        self.transfer_thread.transfer_complete.connect(self.transfer_finished)
        self.transfer_thread.log_message.connect(self.log_message)
        self.transfer_thread.key_generated.connect(self.show_encryption_key)
        
        self.transfer_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        
        self.log_message(f"Transfer başlıyor: {os.path.basename(local_path)} → {remote_path}")
        self.transfer_thread.start()

    def update_progress(self, percent, message):
        self.progress_bar.setValue(percent)
        self.statusBar().showMessage(message)

    def transfer_finished(self, success, message):
        self.log_message(message)
        self.progress_bar.setValue(100 if success else 0)
        self.transfer_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.transfer_thread = None
        self.clean_temp_files()  # Transfer sonrası temizlik

    def log_message(self, message):
        """Log mesajlarını standart formatta kaydet"""
        clean_msg = message
        if "tmp" in message and ".enc" in message:
            clean_msg = message.replace("tmp", "enc_key").replace(".enc", ".bin")
        self.log_area.append(f"[{datetime.now().strftime('%H:%M:%S')}] {clean_msg}")

    def show_encryption_key(self, key):
        """Oluşturulan şifreleme anahtarını göster"""
        self.key_label.setText(f"Şifreleme Anahtarı: {key[:15]}...")  # Kısmi gösterim
        with open('encryption_key.txt', 'w') as f:
            f.write(key)
        self.log_message("🔑 Şifreleme anahtarı 'encryption_key.txt' olarak kaydedildi")

if __name__ == "__main__":
    # Uygulama başlamadan önce temizlik
    temp_dir = tempfile.gettempdir()
    for pattern in ["tmp*.enc", "enc_*.enc", "enc_key.bin"]:
        for file in glob.glob(os.path.join(temp_dir, pattern)):
            try:
                os.remove(file)
            except:
                pass
    
    app = QApplication(sys.argv)
    
    # Public key kontrolü
    if not os.path.exists("server_public.pem"):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("Sunucu public key'i bulunamadı (server_public.pem)")
        msg.setWindowTitle("Güvenlik Uyarısı")
        
        # Anahtar oluşturma butonu ekle
        generate_btn = msg.addButton("Anahtar Oluştur", QMessageBox.ActionRole)
        msg.addButton(QMessageBox.Cancel)
        
        msg.exec_()
        
        if msg.clickedButton() == generate_btn:
            os.system("openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:2048")
            os.system("openssl rsa -pubout -in server_private.pem -out server_public.pem")
            os.chmod("server_private.pem", 0o600)
            QMessageBox.information(None, "Başarılı", "RSA anahtar çifti oluşturuldu!")
        else:
            sys.exit(1)
    
    window = SecureTransferGUI()
    window.show()
    sys.exit(app.exec_())                                                                     # encryption_util.py (Güncellenmiş ve Uyumlu Sürüm)
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