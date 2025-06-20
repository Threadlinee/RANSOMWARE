import os
import sys
import argparse
import getpass
import logging
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Random import get_random_bytes
from datetime import datetime
from typing import List

# Constants
SALT_SIZE = 32
NONCE_SIZE = 16
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024
ITERATIONS = 600_000
SCRYPT_PARAMS = {'N': 16384, 'r': 8, 'p': 1}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FileEncryptor:
    def __init__(self, password: str, use_scrypt: bool = False):
        self.password = password.encode('utf-8')
        self.use_scrypt = use_scrypt

    def _derive_key(self, salt: bytes) -> bytes:
        if self.use_scrypt:
            return scrypt(
                password=self.password,
                salt=salt,
                key_len=32,
                N=SCRYPT_PARAMS['N'],
                r=SCRYPT_PARAMS['r'],
                p=SCRYPT_PARAMS['p']
            )
        return PBKDF2(self.password, salt, dkLen=32, count=ITERATIONS)

    def _get_target_files(self, target_path: str) -> List[str]:
        """Get all files in directory (recursive)"""
        if os.path.isfile(target_path):
            return [target_path]
        elif os.path.isdir(target_path):
            return [
                os.path.join(root, file)
                for root, _, files in os.walk(target_path)
                for file in files
            ]
        raise FileNotFoundError(f"Path not found: {target_path}")

    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt file and remove original"""
        try:
            temp_path = file_path + ".tmp_enc"
            
            salt = get_random_bytes(SALT_SIZE)
            key = self._derive_key(salt)
            cipher = AES.new(key, AES.MODE_GCM)

            with open(file_path, 'rb') as f_in, open(temp_path, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(cipher.nonce)

                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(cipher.encrypt(chunk))

                f_out.write(cipher.digest())

            os.remove(file_path)
            os.rename(temp_path, file_path)
            logger.info(f"Encrypted: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to encrypt {file_path}: {str(e)}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

    def decrypt_file(self, file_path: str) -> bool:
        """Decrypt previously encrypted file"""
        try:
            temp_path = file_path + ".tmp_dec"
            
            with open(file_path, 'rb') as f_in:
                salt = f_in.read(SALT_SIZE)
                nonce = f_in.read(NONCE_SIZE)
                
                # Get file size and tag position
                f_in.seek(0, 2)
                file_size = f_in.tell()
                tag_pos = file_size - TAG_SIZE
                f_in.seek(tag_pos)
                tag = f_in.read(TAG_SIZE)
                f_in.seek(SALT_SIZE + NONCE_SIZE)

                key = self._derive_key(salt)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                with open(temp_path, 'wb') as f_out:
                    remaining = tag_pos - f_in.tell()
                    while remaining > 0:
                        chunk_size = min(CHUNK_SIZE, remaining)
                        chunk = f_in.read(chunk_size)
                        f_out.write(cipher.decrypt(chunk))
                        remaining -= chunk_size

                    cipher.verify(tag)

            os.remove(file_path)
            os.rename(temp_path, file_path)
            logger.info(f"Decrypted: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to decrypt {file_path}: {str(e)}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

def validate_password(password: str) -> bool:
    if len(password) < 12:
        logger.warning("Password must be at least 12 characters")
        return False
    return True

def get_password() -> str:
    while True:
        pwd = getpass.getpass("Enter password: ")
        if not validate_password(pwd):
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pwd == confirm:
            return pwd
        logger.error("Passwords don't match!")

def main():
    parser = argparse.ArgumentParser(
        description="FILE ENCRYPTION/DECRYPTION TOOL (EDUCATIONAL USE ONLY)",
        epilog="WARNING: THIS WILL PERMANENTLY MODIFY FILES!"
    )
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('target', help="File or directory to process")
    parser.add_argument('--scrypt', action='store_true', help="Use scrypt KDF")
    parser.add_argument('--verbose', action='store_true', help="Show debug info")
    
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Warning message
    print("\n" + "!"*80)
    print(f"WARNING: THIS WILL {'ENCRYPT' if args.action == 'encrypt' else 'DECRYPT'} FILES!")
    print("YOU WILL NEED THE PASSWORD TO RECOVER THEM!")
    print("!"*80 + "\n")
    
    confirm = input(f"Are you ABSOLUTELY sure you want to {args.action}? (yes/no): ")
    if confirm.lower() != 'yes':
        logger.info("Operation cancelled")
        return

    try:
        password = get_password()
        encryptor = FileEncryptor(password, args.scrypt)
        
        files = encryptor._get_target_files(args.target)
        if not files:
            logger.error("No files found")
            return

        logger.info(f"Found {len(files)} files to {args.action}")
        
        success_count = 0
        for file in files:
            if args.action == 'encrypt':
                if encryptor.encrypt_file(file):
                    success_count += 1
            else:
                if encryptor.decrypt_file(file):
                    success_count += 1

        logger.info(f"Operation complete. {success_count}/{len(files)} files processed")

    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()