import math
import string
from itertools import permutations
from Crypto.Cipher import ARC4

def shannon_entropy(bytes):
    entropy = 0.0
    size = len(bytes)
    for i in range(256):
        prob = bytes.count(i) / size
        if prob > 0:
            entropy += prob * math.log(prob, 2)
    return -entropy

with open("crypto3.rc4", "rb") as f:
    encrypted = f.read()

print(shannon_entropy(encrypted))

perm = permutations(string.ascii_lowercase, 3)

while True:
    password = ''.join(next(perm))
    cipher = ARC4.new(password.encode())
    test = cipher.encrypt(encrypted)
    entropy = shannon_entropy(test)
    print(f"Testng: {password} - Entropy: {entropy}")
    if entropy < 5.0:
        print(f"Found: {password}")
        break


file = "crypto3.rc4"
key = password.encode()




from Crypto.Cipher import ARC4
with open(file, 'rb') as f:
    ciphertext = f.read()
cipher = ARC4.new(key)
plaintext = cipher.decrypt(ciphertext)
# print(plaintext.decode('utf-8'))
plain = plaintext.decode('utf-8')


def linguistic_analysis(ciphertext):
    # Remove all non-alphabetic characters and convert to lowercase
    ciphertext = ''.join(filter(str.isalpha, ciphertext)).lower()

    # Calculate the frequency of each letter in the ciphertext
    freq = {}
    for letter in ciphertext:
        if letter in freq:
            freq[letter] += 1
        else:
            freq[letter] = 1

    # Calculate the percentage of each letter in the ciphertext
    total = sum(freq.values())
    for letter in freq:
        freq[letter] = freq[letter] / total * 100

    # Calculate the average frequency of each letter in English
    eng_freq = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
        'z': 0.074
    }
    eng_total = sum(eng_freq.values())
    for letter in eng_freq:
        eng_freq[letter] = eng_freq[letter] / eng_total * 100

    # Calculate the difference between the frequency of each letter in the ciphertext and in English
    diff = {}
    for letter in string.ascii_lowercase:
        diff[letter] = freq.get(letter, 0) - eng_freq[letter]

    # Sort the letters by their frequency difference
    sorted_diff = sorted(diff.items(), key=lambda x: x[1], reverse=True)

    # Print the results
    print(f"{'Letter':<10} {'Ciphertext Freq':<20} {'English Freq':<20} {'Difference':<20}")
    for letter, difference in sorted_diff:
        print(f"{letter:<10} {freq.get(letter, 0):<20.2f} {eng_freq[letter]:<20.2f} {difference:<20.2f}")

linguistic_analysis(plain)

def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha() and char.islower():
            # Shift the character by the specified amount
            shifted_char = chr((ord(char.lower()) - ord('a') - shift) % 26 + ord('a'))
            # Preserve the case of the original character
            if char.isupper():
                shifted_char = shifted_char.upper()
            plaintext += shifted_char
        else:
            plaintext += char
    return plaintext

print(caesar_decrypt(plain, 13))

