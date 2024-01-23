from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import random
import string
import hashlib


def encrypt(note, password):
    # Convert the note to bytes
    note = note.encode()

    # Generate a random 16-byte initialization vector
    iv = os.urandom(16)

    # Convert the IV to its hexadecimal string representation
    iv_string = iv.hex()

    # Create a new AES cipher using a 32-byte key
    cipher = AES.new(password.encode(), AES.MODE_CBC, iv)

    # Use the cipher to encrypt the note
    encrypted_note = cipher.encrypt(pad(note, 16))

    # Convert the encrypted note to its hexadecimal string representation
    encrypted_note_string = encrypted_note.hex()

    # Return the encrypted note and the initialization vector as a string
    return encrypted_note_string, iv_string


def decrypt(encrypted_note, iv_string, password):
    # Convert the hexadecimal string back to bytes
    iv = bytes.fromhex(iv_string)

    # Convert the encrypted note from a hexadecimal string to bytes
    encrypted_note = bytes.fromhex(encrypted_note)

    # Create a new AES cipher using the password and the initialization vector
    cipher = AES.new(password.encode(), AES.MODE_CBC, iv)

    # Use the cipher to decrypt the encrypted note
    decrypted_note = unpad(cipher.decrypt(encrypted_note), 16).decode()

    # Return the decrypted note
    return decrypted_note


def generate_salt(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def hash_password(plaintext, salt_length=0, init_salt="", rounds=500):
    if init_salt == "":
        salt = generate_salt(salt_length)
        init_salt = salt
    else:
        salt = init_salt
    for _ in range(rounds):
        plaintext_with_salt = salt + plaintext
        plaintext_bytes = bytes(plaintext_with_salt, 'ascii')
        sha3 = hashlib.sha3_256(plaintext_bytes).hexdigest()
        salt = sha3
    return init_salt + "$" + salt
