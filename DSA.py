from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Funkcja do generowania klucza symetrycznego z hasła
def generate_symmetric_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def DSA_Sign(image_data, private_key):
    signature = private_key.sign(
        image_data,
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def DSA_Verify(image_data, signature, public_key):
    signature = base64.b64decode(signature.encode())
    try:
        public_key.verify(
            signature,
            image_data,
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def DSA_Encrypt(image_data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(image_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data)

def DSA_Decrypt(encrypted_data, key):
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        encrypted_image_data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_image_data) + decryptor.finalize()
    except Exception as e:
        return None

def DSA_Complex(image_data, password, show_result):
    print("DSA")

    # Generowanie klucza DSA
    private_key = dsa.generate_private_key(
        key_size=2048
    )
    public_key = private_key.public_key()

    # Generowanie klucza symetrycznego z hasła
    symmetric_key, salt = generate_symmetric_key(password)

    # Szyfrowanie danych obrazowych
    encrypted_data = DSA_Encrypt(image_data, symmetric_key)

    # Podpisywanie zaszyfrowanych danych obrazowych
    signature = DSA_Sign(encrypted_data, private_key)

    # Weryfikacja podpisu
    is_verified = DSA_Verify(encrypted_data, signature, public_key)

    if show_result:
        print(f"Signature (DSA): {signature}")
        print(f"Signature Verification (DSA): {is_verified}")
        print(f"Salt: {base64.b64encode(salt).decode('utf-8')}")

    # Deszyfrowanie danych obrazowych
    decrypted_data = DSA_Decrypt(encrypted_data, symmetric_key)

    if decrypted_data is None:
        print("Decryption failed.")
        decrypted_data = b''

    return encrypted_data, decrypted_data
