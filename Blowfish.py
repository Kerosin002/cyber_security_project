from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def Blowfish_Encrypt(data, password):
    key = password.encode().ljust(32, b'\0')
    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Zwracamy IV i zaszyfrowane dane

def Blowfish_Decrypt(encrypted_data, password):
    iv = encrypted_data[:8]
    encrypted = encrypted_data[8:]
    key = password.encode().ljust(32, b'\0')

    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted  # Zwracamy odszyfrowane dane jako bytes

def Blowfish_Complex(data, password, show_result):
    print("Blowfish")

    encrypted_data = Blowfish_Encrypt(data, password)
    decrypted_data = Blowfish_Decrypt(encrypted_data, password)

    if show_result:
        print(f"Zaszyfrowane dane (Blowfish): {encrypted_data}")
        print(f"Odszyfrowane dane (Blowfish): {decrypted_data}")

    return encrypted_data, decrypted_data
