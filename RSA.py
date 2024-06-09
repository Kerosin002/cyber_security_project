from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes
from cryptography.hazmat.backends import default_backend
import os

def RSA_Encrypt(data, public_key):
    encrypted = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def RSA_Decrypt(encrypted_data, private_key):
    decrypted = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def AES_Encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def AES_Decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_data

def RSA_Complex(data, password, show_result):
    print("RSA")

    # RSA key generation
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Generate a symmetric key
    symmetric_key = os.urandom(32)  # 256-bit AES key

    # Encrypt the data using AES
    encrypted_data = AES_Encrypt(data, symmetric_key)

    # Encrypt the symmetric key using RSA
    encrypted_symmetric_key = RSA_Encrypt(symmetric_key, public_key)

    # Decrypt the symmetric key using RSA
    decrypted_symmetric_key = RSA_Decrypt(encrypted_symmetric_key, private_key)

    # Decrypt the data using AES
    decrypted_data = AES_Decrypt(encrypted_data, decrypted_symmetric_key)

    if show_result:
        print(f"Zaszyfrowane dane (AES): {encrypted_data}")
        print(f"Zaszyfrowany klucz symetryczny (RSA): {encrypted_symmetric_key}")
        print(f"Odszyfrowane dane (AES): {decrypted_data}")

    return encrypted_symmetric_key + encrypted_data, decrypted_data
