from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def DES_Encrypt(data, password):
    key = password.encode()[:8].ljust(8, b'\0')
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Zwracamy IV i zaszyfrowane dane

def DES_Decrypt(encrypted_data, password):
    iv = encrypted_data[:8]
    encrypted = encrypted_data[8:]
    key = password.encode()[:8].ljust(8, b'\0')

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted  # Zwracamy odszyfrowane dane jako bytes

def DES_Complex(data, password, show_result):
    print("DES")

    encrypted_data = DES_Encrypt(data, password)
    decrypted_data = DES_Decrypt(encrypted_data, password)

    if show_result:    
        print(f"Zaszyfrowane dane (DES): {encrypted_data}")
        print(f"Odszyfrowane dane (DES): {decrypted_data}")

    return encrypted_data, decrypted_data
