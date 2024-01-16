from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


def encrypt(note, password):
    # Convert the note to bytes
    note = note.encode()
    # Generate a random 16-byte initialization vector
    iv = os.urandom(16)

    # Create a new AES cipher using a 32-byte key
    cipher = AES.new(password.encode(), AES.MODE_CBC, iv)
    # Use the cipher to encrypt the note
    encrypted_note = cipher.encrypt(pad(note, 16))
    # Return the encrypted note and the initialization vector
    return encrypted_note, iv


def decrypt(encrypted_note, iv, password):
    # Create a new AES cipher using the password and the initialization vector
    cipher = AES.new(password.encode(), AES.MODE_CBC, iv)

    # Use the cipher to decrypt the encrypted note
    decrypted_note = unpad(cipher.decrypt(encrypted_note), 16).decode()

    # Return the decrypted note
    return decrypted_note

