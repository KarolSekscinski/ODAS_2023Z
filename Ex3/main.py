import os
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import math

file = "file.txt"
key_16 = b"1234567890123456"
key_8 = b"12345678"


# BEGIN: yz9d8a1xj3kq
def add_padding(file_path, block_size):
    """
    Adds PKCS#7 padding to a file.

    :param file_path: The path to the file to pad.
    :param block_size: The block size of the encryption algorithm.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    padded_data = data + padding

    with open(file_path, 'wb') as f:
        f.write(padded_data)
# END: yz9d8a1xj3kq




def encrypt_file(file_path, key, mode, iv=None):
    """
    Encrypts a file using AES or DES in ECB or CBC mode.

    :param file_path: The path to the file to encrypt.
    :param key: The encryption key.
    :param mode: The encryption mode (either 'ECB' or 'CBC').
    :param iv: The initialization vector (required for CBC mode).
    :return: The encrypted data.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    if mode == 'ECB':
        if len(key) == 16:
            cipher = AES.new(key, AES.MODE_ECB)
        elif len(key) == 8:
            cipher = DES.new(key, DES.MODE_ECB)
        else:
            raise ValueError('Invalid key length')
        encrypted_data = cipher.encrypt(data)
    elif mode == 'CBC':
        if len(key) == 16:
            if iv is None:
                iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif len(key) == 8:
            if iv is None:
                iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
        else:
            raise ValueError('Invalid key length')
        encrypted_data = iv + cipher.encrypt(data)
    else:
        raise ValueError('Invalid mode')

    return encrypted_data


def shannon_entropy(bytes):
    entropy = 0.0
    size = len(bytes)
    for i in range(256):
        prob = bytes.count(i) / size
        if prob > 0:
            entropy += prob * math.log(prob, 2)
    return -entropy

cipher_text = add_padding(file, 16)
print(f"Shannon entropy AES with ECB: {shannon_entropy(encrypt_file(file, key_16, 'ECB'))}")

cipher_text = add_padding(file, 8)
print(f'Shannon entropy DES with ECB: {shannon_entropy(encrypt_file(file, key_8, "ECB"))}')

cipher_text = add_padding(file, 16)
print(f'Shannon entropy AES with CBC: {shannon_entropy(encrypt_file(file, key_16, "CBC"))}')

cipher_text = add_padding(file, 8)
print(f'Shannon entropy DES with CBC: {shannon_entropy(encrypt_file(file, key_8, "CBC"))}')
