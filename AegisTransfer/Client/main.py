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
    """Load server's public key / Sunucunun public key'ini yükle"""
    try:
        with open("server_public.pem", "rb") as f:
            return load_pem_public_key(f.read())
    except Exception as e:
        print(f"Public key loading error / Public key yükleme hatası: {str(e)}")
        return None

class EncryptionManager:
    def __init__(self, key=None):
        """
        Initialize encryption manager with optional key
        Şifreleme yöneticisini isteğe bağlı anahtarla başlat
        
        Args:
            key: Encryption key (bytes or str) / Şifreleme anahtarı (bytes veya str)
        """
        if key:
            self.key = base64.urlsafe_b64encode(key).decode() if isinstance(key, bytes) else key
        else:
            self.key = Fernet.generate_key().decode()
        
        self.cipher = Fernet(self.key.encode())

    def encrypt_file(self, file_path):
        """
        Encrypt file and return encrypted file path
        Dosyayı şifreler ve şifrelenmiş dosya yolunu döndürür
        
        Returns:
            tuple: (encrypted_file_path, encryption_key)
                   (şifrelenmiş_dosya_yolu, şifreleme_anahtarı)
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.cipher.encrypt(data)
        
        # Create temp file with standard naming
        # Standart isimlendirme ile geçici dosya oluştur
        temp_dir = os.path.dirname(file_path) or tempfile.gettempdir()
        temp_filename = f"enc_{os.path.basename(file_path)}.enc"
        temp_filepath = os.path.join(temp_dir, temp_filename)
        
        with open(temp_filepath, 'wb') as f:
            f.write(encrypted_data)
        
        return temp_filepath, self.key

    def save_key(self, key_path='encryption_key.key'):
        """Save encryption key to file / Şifreleme anahtarını dosyaya kaydet"""
        with open(key_path, 'w') as f:
            f.write(self.key)

# ======================== SECURE TRANSFER ===========================
class SecureTransfer:
    def __init__(self):
        """Initialize secure file transfer / Güvenli dosya transferini başlat"""
        self.ssh = None
        self._initialize_ssh()
    
    def _initialize_ssh(self):
        """Initialize SSH client / SSH istemcisini başlat"""
        if self.ssh is not None:
            self.ssh.close()
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    def connect(self, host, username, password):
        """
        Connect to SSH server / SSH sunucusuna bağlan
        
        Args:
            host: Server address / Sunucu adresi
            username: Login username / Kullanıcı adı
            password: Login password / Şifre
            
        Returns:
            bool: True if connection successful / Bağlantı başarılıysa True
        """
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
            raise Exception(f"SSH Connection Error / SSH Bağlantı Hatası: {str(e)}")
    
    def transfer_file(self, local_path, remote_path, callback=None):
        """
        Transfer file securely / Dosyayı güvenli şekilde transfer et
        
        Args:
            local_path: Local file path / Yerel dosya yolu
            remote_path: Remote destination path / Uzak hedef yolu
            callback: Progress callback function / İlerleme geri çağırım fonksiyonu
        """
        try:
            with self.ssh.open_sftp() as sftp:
                sftp.put(local_path, remote_path, callback=callback)
            return True
        except Exception as e:
            raise Exception(f"Transfer Error / Transfer Hatası: {str(e)}")
    
    def close(self):
        """Close SSH connection / SSH bağlantısını kapat"""
        if self.ssh:
            self.ssh.close()

# ======================= TRANSFER THREAD ============================
class TransferThread(QThread):
    """Thread for handling file transfers / Dosya transferlerini yönetmek için thread"""
    update_progress = pyqtSignal(int, str)
    transfer_complete = pyqtSignal(bool, str)
    log_message = pyqtSignal(str)
    key_generated = pyqtSignal(str)

    def __init__(self, local_path, remote_path, host, username, password, encrypt=False):
        """
        Initialize transfer thread / Transfer thread'ini başlat
        
        Args:
            local_path: Source file path / Kaynak dosya yolu
            remote_path: Destination path / Hedef yol
            host: Server address / Sunucu adresi
            username: SSH username / SSH kullanıcı adı
            password: SSH password / SSH şifresi
            encrypt: Whether to encrypt / Şifreleme yapılıp yapılmayacağı
        """
        super().__init__()
        self.local_path = local_path
        self.remote_path = remote_path
        self.host = host
        self.username = username
        self.password = password
        self.encrypt = encrypt
        self._is_running = True

    def run(self):
        """Main transfer execution / Ana transfer işlemi"""
        temp_file = None
        encrypted_key = None
        try:
            # Calculate file hash / Dosya hash'ini hesapla
            file_hash = self.calculate_file_hash(self.local_path)
            self.log_message.emit(f"File SHA256 Hash / Dosya SHA256 Hash: {file_hash}")

            if self.encrypt:
                # Encrypt file / Dosyayı şifrele
                enc_manager = EncryptionManager(rsa_mode=True)
                temp_file, encrypted_key = enc_manager.encrypt_file(self.local_path)
                self.local_path = temp_file
                self.log_message.emit(f"Encrypted (AES-GCM) / Şifrelendi (AES-GCM): {os.path.basename(temp_file)}")
                
                # Save encrypted key / Şifrelenmiş anahtarı kaydet
                encrypted_key_path = os.path.join(tempfile.gettempdir(), "enc_key.bin")
                with open(encrypted_key_path, "wb") as f:
                    f.write(encrypted_key)
                self.log_message.emit("AES key encrypted with RSA / AES anahtarı RSA ile şifrelendi (enc_key.bin)")

            # Transfer operations / Transfer işlemleri
            transfer = SecureTransfer()
            transfer.connect(self.host, self.username, self.password)
        
            def progress_callback(sent, total):
                """Progress update callback / İlerleme güncelleme geri çağırımı"""
                percent = int((sent/total) * 100)
                self.update_progress.emit(percent, f"{sent}/{total} bytes / bayt")
        
            # Transfer main file / Ana dosyayı transfer et
            remote_filename = os.path.basename(self.local_path)
            final_remote_path = os.path.join(self.remote_path, remote_filename)
            transfer.transfer_file(self.local_path, final_remote_path, progress_callback)
        
            # Transfer encrypted key if exists / Şifrelenmiş anahtarı transfer et (varsa)
            if self.encrypt and encrypted_key:
                key_remote_path = os.path.join(self.remote_path, "enc_key.bin")
                transfer.transfer_file(encrypted_key_path, key_remote_path)
                self.log_message.emit("Encrypted key transferred / Şifrelenmiş anahtar transfer edildi")
        
            transfer.close()
            self.transfer_complete.emit(True, "Transfer completed successfully! / Transfer başarıyla tamamlandı!")
        
        except Exception as e:
            self.transfer_complete.emit(False, f"Error / Hata: {str(e)}")
        finally:
            # Clean temp files / Geçici dosyaları temizle
            for file_path in [temp_file, encrypted_key_path if 'encrypted_key_path' in locals() else None]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        self.log_message.emit(f"Cleanup error / Temizleme hatası: {str(e)}")

    def calculate_file_hash(self, file_path):
        """
        Calculate SHA256 hash of file / Dosyanın SHA256 hash'ini hesapla
        
        Args:
            file_path: Path to file / Dosya yolu
            
        Returns:
            str: Hexadecimal hash string / Hexadecimal hash string
        """
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

# ======================== MAIN GUI =================================
class SecureTransferGUI(QMainWindow):
    """Main application GUI / Ana uygulama arayüzü"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Transfer v2.1 / Güvenli Dosya Transferi v2.1")
        self.setGeometry(100, 100, 800, 600)
        self.clean_temp_files()  # Initial cleanup / Başlangıçta temizlik
        self.init_ui()
        self.transfer_thread = None

    def clean_temp_files(self):
        """Clean temporary files / Geçici dosyaları temizle"""
        temp_dir = tempfile.gettempdir()
        for pattern in ["tmp*.enc", "enc_*.enc"]:
            for file in glob.glob(os.path.join(temp_dir, pattern)):
                try:
                    os.remove(file)
                    self.log_message(f"Cleaned temp file / Temizlenen geçici dosya: {os.path.basename(file)}")
                except Exception as e:
                    self.log_message(f"Cleanup error / Temizleme hatası: {str(e)}")

    def init_ui(self):
        """Initialize user interface / Kullanıcı arayüzünü başlat"""
        main_widget = QWidget()
        main_layout = QVBoxLayout()

        # Connection Settings / Bağlantı Ayarları
        connection_group = QGroupBox("Connection Settings / Bağlantı Ayarları")
        connection_layout = QVBoxLayout()
        
        # Host
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("192.168.1.40")
        host_layout.addWidget(self.host_input)
        connection_layout.addLayout(host_layout)

        # Username / Kullanıcı Adı
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Username / Kullanıcı Adı:"))
        self.user_input = QLineEdit("ares")
        user_layout.addWidget(self.user_input)
        connection_layout.addLayout(user_layout)

        # Password / Şifre
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Password / Şifre:"))
        self.pass_input = QLineEdit("123")
        self.pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(self.pass_input)
        connection_layout.addLayout(pass_layout)

        connection_group.setLayout(connection_layout)
        main_layout.addWidget(connection_group)

        # File Transfer / Dosya Transferi
        transfer_group = QGroupBox("File Transfer / Dosya Transferi")
        transfer_layout = QVBoxLayout()

        # File Selection / Dosya Seçimi
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select file to transfer... / Transfer edilecek dosyayı seçin...")
        file_layout.addWidget(self.file_input)
        browse_btn = QPushButton("Browse / Gözat")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        transfer_layout.addLayout(file_layout)

        # Remote Directory / Uzak Dizin
        remote_layout = QHBoxLayout()
        remote_layout.addWidget(QLabel("Remote Directory / Uzak Dizin:"))
        self.remote_input = QLineEdit("/home/ares/")
        remote_layout.addWidget(self.remote_input)
        transfer_layout.addLayout(remote_layout)

        # Encryption Option / Şifreleme Seçeneği
        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Encryption / Şifreleme:"))
        self.encrypt_combo = QComboBox()
        self.encrypt_combo.addItems(["Enabled / Açık", "Disabled / Kapalı"])
        options_layout.addWidget(self.encrypt_combo)
        
        # Key Display / Anahtar Görüntüleme
        self.key_label = QLabel("Encryption Key / Şifreleme Anahtarı")
        options_layout.addWidget(self.key_label)
        
        transfer_layout.addLayout(options_layout)

        # Progress Bar / İlerleme Çubuğu
        self.progress_bar = QProgressBar()
        transfer_layout.addWidget(self.progress_bar)

        # Buttons / Butonlar
        button_layout = QHBoxLayout()
        self.transfer_btn = QPushButton("Start Transfer / Transferi Başlat")
        self.transfer_btn.clicked.connect(self.start_transfer)
        button_layout.addWidget(self.transfer_btn)

        self.cancel_btn = QPushButton("Cancel / İptal")
        self.cancel_btn.setEnabled(False)
        button_layout.addWidget(self.cancel_btn)

        transfer_layout.addLayout(button_layout)
        transfer_group.setLayout(transfer_layout)
        main_layout.addWidget(transfer_group)

        # Log Area / Kayıt Alanı
        log_group = QGroupBox("Logs / Kayıtlar")
        log_layout = QVBoxLayout()
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        log_layout.addWidget(self.log_area)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def browse_file(self):
        """File selection dialog / Dosya seçim diyaloğu"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File / Dosya Seç")
        if file_path:
            clean_path = os.path.normpath(file_path)
            self.file_input.setText(clean_path)

    def start_transfer(self):
        """Start file transfer / Dosya transferini başlat"""
        local_path = self.file_input.text()
        remote_path = os.path.join(
            self.remote_input.text(),
            os.path.basename(local_path) + (".enc" if "Açık" in self.encrypt_combo.currentText() else "")
        )

        if not os.path.exists(local_path):
            QMessageBox.warning(self, "Error / Hata", "Please select a valid file! / Lütfen geçerli bir dosya seçin!")
            return

        self.transfer_thread = TransferThread(
            local_path=local_path,
            remote_path=remote_path,
            host=self.host_input.text(),
            username=self.user_input.text(),
            password=self.pass_input.text(),
            encrypt="Açık" in self.encrypt_combo.currentText()
        )
        
        self.transfer_thread.update_progress.connect(self.update_progress)
        self.transfer_thread.transfer_complete.connect(self.transfer_finished)
        self.transfer_thread.log_message.connect(self.log_message)
        self.transfer_thread.key_generated.connect(self.show_encryption_key)
        
        self.transfer_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        
        self.log_message(f"Starting transfer: {os.path.basename(local_path)} → {remote_path} / Transfer başlıyor: {os.path.basename(local_path)} → {remote_path}")
        self.transfer_thread.start()

    def update_progress(self, percent, message):
        """Update progress bar / İlerleme çubuğunu güncelle"""
        self.progress_bar.setValue(percent)
        self.statusBar().showMessage(message)

    def transfer_finished(self, success, message):
        """Handle transfer completion / Transfer tamamlanınca işle"""
        self.log_message(message)
        self.progress_bar.setValue(100 if success else 0)
        self.transfer_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.transfer_thread = None
        self.clean_temp_files()  # Post-transfer cleanup / Transfer sonrası temizlik

    def log_message(self, message):
        """Log messages with timestamp / Zaman damgalı log mesajları"""
        clean_msg = message
        if "tmp" in message and ".enc" in message:
            clean_msg = message.replace("tmp", "enc_key").replace(".enc", ".bin")
        self.log_area.append(f"[{datetime.now().strftime('%H:%M:%S')}] {clean_msg}")

    def show_encryption_key(self, key):
        """Display generated encryption key / Oluşturulan şifreleme anahtarını göster"""
        self.key_label.setText(f"Encryption Key / Şifreleme Anahtarı: {key[:15]}...")  # Partial display / Kısmi gösterim
        with open('encryption_key.txt', 'w') as f:
            f.write(key)
        self.log_message("🔑 Encryption key saved as 'encryption_key.txt' / Şifreleme anahtarı 'encryption_key.txt' olarak kaydedildi")

if __name__ == "__main__":
    # Cleanup before starting / Başlamadan önce temizlik
    temp_dir = tempfile.gettempdir()
    for pattern in ["tmp*.enc", "enc_*.enc", "enc_key.bin"]:
        for file in glob.glob(os.path.join(temp_dir, pattern)):
            try:
                os.remove(file)
            except:
                pass
    
    app = QApplication(sys.argv)
    
    # Public key check / Public key kontrolü
    if not os.path.exists("server_public.pem"):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("Server public key not found (server_public.pem) / Sunucu public key'i bulunamadı (server_public.pem)")
        msg.setWindowTitle("Security Warning / Güvenlik Uyarısı")
        
        # Add key generation button / Anahtar oluşturma butonu ekle
        generate_btn = msg.addButton("Generate Key / Anahtar Oluştur", QMessageBox.ActionRole)
        msg.addButton(QMessageBox.Cancel)
        
        msg.exec_()
        
        if msg.clickedButton() == generate_btn:
            os.system("openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:2048")
            os.system("openssl rsa -pubout -in server_private.pem -out server_public.pem")
            os.chmod("server_private.pem", 0o600)
            QMessageBox.information(None, "Success / Başarılı", "RSA key pair generated! / RSA anahtar çifti oluşturuldu!")
        else:
            sys.exit(1)
    
    window = SecureTransferGUI()
    window.show()
    sys.exit(app.exec_())