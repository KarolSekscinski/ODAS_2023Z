import hashlib
import random
import string

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def sha1_hash(text, salt="z"):
    text_with_salt = text + salt
    sha1 = hashlib.sha1(text_with_salt.encode()).hexdigest()
    return "$sha1$" + salt + "$" + sha1

dicto = {}

while True:
    random_string = generate_random_string(5)
    rhash = sha1_hash(random_string)
    xd = dicto.get(rhash.split("$")[3][:12])
    print(random_string)
    if xd is not None and xd != random_string:
        print(rhash)
        print("Found it! " + random_string)
        print("Hash of " + xd + " is " + sha1_hash(xd))
        print("Hash of " + random_string + " is " + sha1_hash(random_string))
        break
    dicto[rhash.split("$")[3][:12]] = random_string
