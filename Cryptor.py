import os
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag

# Function to derive a key from password and salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires a 32-byte key
        salt=salt,
        iterations=100000,  # A high number of iterations for security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file
def encrypt_file(file_path: str, password: str):
    try:
        with open(file_path, "rb") as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return

    # Generate a random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(12)  # GCM recommended IV length is 12 bytes

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Write salt, IV, ciphertext, and tag to the encrypted file
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as f:
        f.write(salt)
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)

    print(f"File encrypted successfully: {encrypted_file_path}")

# Function to decrypt a file
def decrypt_file(encrypted_file_path: str, password: str):
    try:
        with open(encrypted_file_path, "rb") as f:
            salt = f.read(16)
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()
    except FileNotFoundError:
        print(f"Error: Encrypted file not found at {encrypted_file_path}")
        return

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        print("Error: Decryption failed. Incorrect password or corrupted file.")
        return

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    original_file_path = encrypted_file_path.replace(".encrypted", "")
    with open(original_file_path, "wb") as f:
        f.write(plaintext)

    print(f"File decrypted successfully: {original_file_path}")

def main():
    parser = argparse.ArgumentParser(description="Secure File Cryptographer")
    parser.add_argument("--encrypt", help="Path to the file to encrypt")
    parser.add_argument("--decrypt", help="Path to the file to decrypt")
    parser.add_argument("--password", required=True, help="Password for encryption/decryption")

    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.encrypt, args.password)
    elif args.decrypt:
        decrypt_file(args.decrypt, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()


