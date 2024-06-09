from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def AES_Encrypt(data, password):
    backend = default_backend()
    key = password.encode()  # Zakładamy, że hasło jest typu str i kodujemy je do bytes
    key = key.ljust(32, b'\0')[:32]  # Wymuszenie klucza o długości 32 bajtów (256 bitów)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Zwracamy iv i zaszyfrowane dane


def AES_Decrypt(encrypted_data, password):
    iv = encrypted_data[:16]
    encrypted = encrypted_data[16:]

    key = password.encode()  # Zakładamy, że hasło jest typu str i kodujemy je do bytes
    key = key.ljust(32, b'\0')[:32]  # Wymuszenie klucza o długości 32 bajtów (256 bitów)

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted  # Zwracamy odszyfrowane dane jako bytes


def AES_Complex(data, password, show_result):
    print("AES")

    encrypted_data = AES_Encrypt(data, password)
    decrypted_data = AES_Decrypt(encrypted_data, password)
    
    if show_result:
        print(f"Zaszyfrowane dane: {encrypted_data}")
        print(f"Odszyfrowane dane: {decrypted_data}")

    return encrypted_data, decrypted_data
