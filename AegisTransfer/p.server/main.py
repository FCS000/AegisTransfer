#!/usr/bin/env python3
"""
HEP File Decryptor - Enhanced Version
HEP Dosya Şifre Çözücü - Gelişmiş Sürüm
"""

import os
import sys
import glob
import logging
from pathlib import Path
from colorama import Fore, init
from encryption_util import EncryptionManager

# Renkli çıktı için colorama başlatma
init(autoreset=True)

BASE_DIR = Path(__file__).parent.absolute()

# Log ayarları
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(BASE_DIR / 'decryptor.log', mode='w'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def validate_environment():
    """Gerekli dosyaları ve izinleri kontrol eder / Checks required files and permissions"""
    required_files = {
        "public_key": BASE_DIR / "server_public.pem",
        "private_key": BASE_DIR / "server_private.pem"
    }
    
    for name, path in required_files.items():
        if not path.exists():
            logger.error(f"Missing {name} file: {path}")
            print(Fore.RED + f"❌ Hata: {name} dosyası eksik: {path}")
            sys.exit(1)
        
        if name == "private_key":
            current_mode = os.stat(path).st_mode & 0o777
            if current_mode != 0o600:
                try:
                    os.chmod(path, 0o600)
                    logger.info(f"Fixed permissions for {path} (was {oct(current_mode)}, now 0o600)")
                except Exception as e:
                    logger.error(f"Failed to set permissions for {path}: {e}")
                    print(Fore.RED + f"❌ Hata: Private key izinleri ayarlanamadı")
                    sys.exit(1)

def find_encrypted_files():
    """Şifrelenmiş dosyaları ve anahtarlarını bulur / Finds encrypted files with their keys"""
    enc_files = []
    # Tüm .enc dosyalarını bul (alt dizinler dahil)
    for root, _, files in os.walk(BASE_DIR):
        for file in files:
            if file.endswith('.enc'):
                enc_files.append(os.path.join(root, file))
    
    # Eşleşen anahtarları bul
    matches = []
    for enc_file in enc_files:
        enc_dir = os.path.dirname(enc_file)
        base_name = os.path.basename(enc_file)
        
        # Önce aynı dizindeki anahtarlara bak
        possible_keys = [
            os.path.join(enc_dir, base_name.replace('.enc', '.key')),
            os.path.join(enc_dir, 'enc_key.bin'),
            os.path.join(enc_dir, 'enc_key_fixed.bin'),
            os.path.join(BASE_DIR, 'enc_key.bin'),
            os.path.join(BASE_DIR, 'enc_key_fixed.bin')
        ]
        
        for key_file in possible_keys:
            if os.path.exists(key_file):
                matches.append((enc_file, key_file))
                break
        else:
            logger.warning(f"{enc_file} için anahtar bulunamadı")
    
    return matches

def decrypt_and_save(enc_file, key_file):
    """Dosyanın şifresini çözüp kaydeder / Decrypts file and saves with error handling"""
    try:
        # Windows yol ayraçlarını düzelt
        enc_file = enc_file.replace('\\', '/')
        key_file = key_file.replace('\\', '/')
        
        # Mutlak yola çevir
        enc_file = str(Path(enc_file).absolute())
        key_file = str(Path(key_file).absolute())
        
        logger.info(f"Şifre çözme denemesi: {enc_file} with {key_file}")
        
        # Dosya varlık kontrolü
        if not Path(enc_file).is_file():
            available = list(Path(enc_file).parent.glob('*'))
            raise FileNotFoundError(
                f"Şifrelenmiş dosya bulunamadı!\n"
                f"İstenen: {enc_file}\n"
                f"Mevcut: {[str(p) for p in available]}"
            )

        if not Path(enc_file).exists():
            raise FileNotFoundError(f"Şifrelenmiş dosya bulunamadı: {enc_file}")
        if not Path(key_file).exists():
            raise FileNotFoundError(f"Anahtar dosyası bulunamadı: {key_file}")

        # Anahtar dosyasını oku
        with open(key_file, 'rb') as f:
            key_data = f.read()
            logger.info(f"Anahtar dosyası okundu ({len(key_data)} bayt)")

        # Otomatik mod seçimi
        em = EncryptionManager(rsa_mode=len(key_data) == 256)
        
        # Şifre çözme
        decrypted_data = em.decrypt_file(enc_file, key_data)

        # Çıktı dizinini hazırla
        output_dir = Path(__file__).parent / "decrypted_files"
        output_dir.mkdir(exist_ok=True, mode=0o750)
        
        # Çıktı dosya adı oluştur
        output_file = output_dir / f"{Path(enc_file).stem}.decrypted"
        
        # Şifresi çözülmüş veriyi kaydet
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        logger.info(f"Başarıyla kaydedildi: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"{enc_file} şifresi çözülemedi: {str(e)}", exc_info=True)
        print(Fore.RED + f"\n❌ Şifre çözme başarısız: {str(e)}")
        return False

def main():
    print(Fore.YELLOW + "\n🔓 HEP Dosya Şifre Çözücü Başlatılıyor...")
    logger.info("HEP Dosya Şifre Çözücü Başlatıldı")
    
    validate_environment()

    # Komut satırı argümanlarını işle
    if len(sys.argv) == 3:
        # Manuel mod: python main.py encrypted.file enc_key.bin
        success = decrypt_and_save(sys.argv[1], sys.argv[2])
        sys.exit(0 if success else 1)
    elif len(sys.argv) == 2 and sys.argv[1] == "--auto":
        # Otomatik mod: tüm şifrelenmiş dosyaları bul ve çöz
        matches = find_encrypted_files()
        if not matches:
            logger.error("Otomatik modda eşleşen şifrelenmiş dosya bulunamadı")
            print(Fore.RED + "❌ Eşleşen şifrelenmiş dosya bulunamadı")
            sys.exit(1)
            
        all_success = True
        for enc_file, key_file in matches:
            if not decrypt_and_save(enc_file, key_file):
                all_success = False
                
        sys.exit(0 if all_success else 1)
    else:
        # Kullanım bilgisi göster
        logger.error("Geçersiz komut satırı argümanları")
        print(Fore.CYAN + "\nKullanım:")
        print(Fore.CYAN + "  Otomatik mod: python main.py --auto")
        print(Fore.CYAN + "  Manuel mod: python main.py <şifrelenmiş_dosya> <anahtar_dosyası>")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Beklenmeyen hata: {str(e)}", exc_info=True)
        print(Fore.RED + f"\n💀 Kritik hata: {str(e)}")
        sys.exit(1)