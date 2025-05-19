from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from datetime import datetime
from sys import stderr, stdout
import os
import argparse
import secrets
import hashlib

class EncodingError(Exception):
    pass

class CFileError(Exception):
    pass

class Encryptor:
    def __init__(self, key: str, iv: bytes):
        self.key = key
        self.iv = iv
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, data: bytes) -> bytes:
        salt = secrets.token_bytes(16)
        key = self.derive_key(self.key, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return salt + encrypted_data

    def decrypt(self, encrypted_data: bytes) -> bytes:
        salt = encrypted_data[:16]
        key = self.derive_key(self.key, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
    
class Logger:
    def __init__(self, verbose=False, file: Path = None):
        self.verbose = verbose
        self.file = file
        if file != None and not os.path.exists(file):
            self.file = file.touch()
        
    def set_verbose(self, verbose):
        self.verbose = verbose
        
    def log(self, message, file=stdout):
        if self.file != None:
            file = open(self.file, "a")
        
        if self.verbose:
            print(f'{datetime.now()} - LOG: {message}', file=file)
            
    def warn(self, message, file=stderr):
        if self.file != None:
            file = open(self.file, "a")
            
        print(f'{datetime.now()} - ALERT: {message}', file=file)
        
    def error(self, message, file=stderr):
        if self.file != None:
            file = open(self.file, "a")
            
        print(f'{datetime.now()} - PANIC: {message}', file=file)
        exit(1)
        
def manage_file(path: Path, encrypt: bool, decrypt: bool, logger: Logger, cipher: Encryptor):
    if not encrypt and not decrypt:
        raise EncodingError("No locker mode passed.")
    
    temp = f'{path}.tmp~'
    try:
        with open(path, "rb") as f, open(temp, "wb") as a:
            if encrypt:
                logger.log(f'Encrypting {path}.')
                a.write(cipher.encrypt(f.read()))
                
            elif decrypt:
                logger.log(f'Decrypting {path}.')
                a.write(cipher.decrypt(f.read()))
                    
            f.close()
            a.close()
        
        os.replace(temp, path)
        
    except Exception as e:
        if os.path.exists(temp): os.remove(temp)
        raise CFileError(f'Failed to process file {path}: {e}.')
        
def locker(path: Path, encrypt: bool, decrypt: bool, isRecursive: bool, isInteractive: bool, logger: Logger, cipher: Encryptor):
    for child in path.iterdir():
        if child.is_file():
            manage_file(child, encrypt, decrypt, logger, cipher)
            
        elif child.is_dir():
            logger.log(f'Looking for processing {child}.')
            if isRecursive:
                confirmed = True
            elif isInteractive:
                confirmed = 'y' in input(f'Lock/Unlock {child} folder? [No/Yes]: ').lower()
            else:
                confirmed = False
                
            if confirmed:
                logger.log(f'Confirmed processing {child}.')
                locker(child, encrypt, decrypt, isRecursive, isInteractive, logger, cipher)
            else:
                logger.warn(f'Skipping file {child} because of no -r or -i passed.')
                continue    
            
        else:
            raise CFileError("File type not supported.")
        
def cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="locker",
        description="CLI tool to lock folders.",
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Lock directories and all subdirectories."
    )
    
    group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Ask about the actions being performed."
    )
    
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument(
        "-c", "--encrypt", "--lock",
        action="store_true",
        help="Select encription mode to locker"
    )
    
    group2.add_argument(
        "-d", "--decrypt", "--unlock",
        action="store_true",
        help="Select decription mode to locker"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show more detail about actions being performed."
    )
    
    parser.add_argument(
        "path",
        type=Path,
        help="The source directory of the lock."
    )
    
    parser.add_argument(
        "key",
        type=str,
        help="The password to encrypt/decrypt data."
    )
    
    parser.add_argument(
        "-o", "--output",
        required=False,
        type=Path,
        metavar="FILE",
        help="Store the log in a external file."
    )
    
    return parser.parse_args()
        
def main():
    args = cli()
    
    if args.output:
        logger = Logger(args.verbose, file=args.output)
    else:
        logger = Logger(args.verbose)
        
    cipher = Encryptor(args.key, hashlib.sha256(args.key.encode()).digest()[:16])
    
    try:
        logger.log("Starting process...")
        locker(args.path, args.encrypt, args.decrypt, args.recursive, args.interactive, logger, cipher)
    
    except EncodingError as e:
        logger.error(e)
        
    except CFileError as e:
        logger.error(e)
        
    except KeyboardInterrupt:
        logger.error("Keyboard Interrupt signal detected.")

if __name__ == "__main__":
    main()