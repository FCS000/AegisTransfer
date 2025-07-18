#!/usr/bin/env python3
"""
HEP File Decryptor - Enhanced Version
"""

import os
import sys
import glob
import logging
from pathlib import Path
from colorama import Fore, init
from encryption_util import EncryptionManager

# Initialize colorama
init(autoreset=True)

BASE_DIR = Path(__file__).parent.absolute()

# Configure logging
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
    """Check required files and permissions"""
    required_files = {
        "public_key": BASE_DIR / "server_public.pem",
        "private_key": BASE_DIR / "server_private.pem"
    }
    
    for name, path in required_files.items():
        if not path.exists():
            logger.error(f"Missing {name} file: {path}")
            print(Fore.RED + f"❌ Error: Missing {name} file: {path}")
            sys.exit(1)
        
        if name == "private_key":
            current_mode = os.stat(path).st_mode & 0o777
            if current_mode != 0o600:
                try:
                    os.chmod(path, 0o600)
                    logger.info(f"Fixed permissions for {path} (was {oct(current_mode)}, now 0o600)")
                except Exception as e:
                    logger.error(f"Failed to set permissions for {path}: {e}")
                    print(Fore.RED + f"❌ Error: Failed to set permissions for private key")
                    sys.exit(1)

def find_encrypted_files():
    """Find encrypted files with their keys"""
    enc_files = []
    # Find all .enc files (recursive)
    for root, _, files in os.walk(BASE_DIR):
        for file in files:
            if file.endswith('.enc'):
                enc_files.append(os.path.join(root, file))
    
    # Find matching keys
    matches = []
    for enc_file in enc_files:
        enc_dir = os.path.dirname(enc_file)
        base_name = os.path.basename(enc_file)
        
        # First look for keys in the same directory
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
            logger.warning(f"No key found for: {enc_file}")
    
    return matches

def decrypt_and_save(enc_file, key_file):
    """Decrypt file and save with proper error handling"""
    try:
        # Windows yol ayraçlarını düzelt
        enc_file = enc_file.replace('\\', '/')
        key_file = key_file.replace('\\', '/')
        
        # Mutlak yola çevir
        enc_file = str(Path(enc_file).absolute())
        key_file = str(Path(key_file).absolute())
        
        logger.info(f"Attempting to decrypt: {enc_file} with {key_file}")
        
        # Kesin dosya varlık kontrolü
        if not Path(enc_file).is_file():
            available = list(Path(enc_file).parent.glob('*'))
            raise FileNotFoundError(
                f"Encrypted file not found!\n"
                f"Requested: {enc_file}\n"
                f"Available: {[str(p) for p in available]}"
            )

        # File existence checks
        if not Path(enc_file).exists():
            raise FileNotFoundError(f"Encrypted file not found: {enc_file}")
        if not Path(key_file).exists():
            raise FileNotFoundError(f"Key file not found: {key_file}")

        # Read key file
        with open(key_file, 'rb') as f:
            key_data = f.read()
            logger.info(f"Read key file ({len(key_data)} bytes)")

        # Automatic mode selection
        em = EncryptionManager(rsa_mode=len(key_data) == 256)
        
        # Decryption
        decrypted_data = em.decrypt_file(enc_file, key_data)

        # Prepare output directory
        output_dir = Path(__file__).parent / "decrypted_files"
        output_dir.mkdir(exist_ok=True, mode=0o750)
        
        # Create output filename
        output_file = output_dir / f"{Path(enc_file).stem}.decrypted"
        
        # Save decrypted data
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        logger.info(f"Successfully saved to: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to decrypt {enc_file}: {str(e)}", exc_info=True)
        print(Fore.RED + f"\n❌ Decryption failed: {str(e)}")
        return False

def main():
    print(Fore.YELLOW + "\n🔓 HEP File Decryptor Initializing...")
    logger.info("Starting HEP File Decryptor")
    
    validate_environment()

    # Handle command line arguments
    if len(sys.argv) == 3:
        # Manual mode: python main.py encrypted.file enc_key.bin
        success = decrypt_and_save(sys.argv[1], sys.argv[2])
        sys.exit(0 if success else 1)
    elif len(sys.argv) == 2 and sys.argv[1] == "--auto":
        # Auto mode: find and decrypt all
        matches = find_encrypted_files()
        if not matches:
            logger.error("No matching encrypted files found in auto mode")
            print(Fore.RED + "❌ No matching encrypted files found")
            sys.exit(1)
            
        all_success = True
        for enc_file, key_file in matches:
            if not decrypt_and_save(enc_file, key_file):
                all_success = False
                
        sys.exit(0 if all_success else 1)
    else:
        # Show usage
        logger.error("Invalid command line arguments")
        print(Fore.CYAN + "\nUsage:")
        print(Fore.CYAN + "  Auto mode: python main.py --auto")
        print(Fore.CYAN + "  Manual mode: python main.py <encrypted_file> <key_file>")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Unexpected error: {str(e)}", exc_info=True)
        print(Fore.RED + f"\n💀 Critical error: {str(e)}")
        sys.exit(1)
