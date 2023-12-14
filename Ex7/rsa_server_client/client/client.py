import requests, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

STATUS_OK = 200


class Client:
    def __init__(self, server_url):
        self.server_url = server_url

    def send_key(self, uid, key):
        url = self.server_url + '/key/' + uid
        data = {'key': key.decode()}
        response = requests.post(url, json=data)
        if response.status_code != STATUS_OK:
            raise Exception(f'FAIL({response.status_code}): {response.text}')
        print(f'SUCCESS: {response.text}')

    def get_key(self, uid):
        url = self.server_url + '/key/' + uid
        response = requests.get(url)
        if response.status_code != STATUS_OK:
            raise Exception(f'FAIL({response.status_code}): {response.text}')

        key = response.text.encode()
        return key

    def send_binary_message(self, uid, msg):
        txt = base64.encodebytes(msg).decode()
        self.send_text_message(uid, txt)

    def send_text_message(self, uid, msg):
        url = self.server_url + '/message/' + uid
        data = {'message': msg}
        response = requests.post(url, json=data)
        if response.status_code != STATUS_OK:
            raise Exception(f'FAIL({response.status_code}): {response.text}')
        print(f'SUCCESS: {response.text}')

    def get_text_message(self, uid):
        url = self.server_url + '/message/' + uid
        response = requests.get(url)
        if response.status_code != STATUS_OK:
            raise Exception(f'FAIL({response.status_code}): {response.text}')

        txt = response.text
        return txt

    def get_binary_message(self, uid):
        txt = self.get_text_message(uid)
        msg = base64.decodebytes(txt.encode())
        return msg
# code above is from exercise   
    def send_signed_message(self, message, do_kogo_uid):
        c = Client("http://127.0.0.1:5555")
        key_string = c.get_key(do_kogo_uid)
        pub_key = RSA.import_key(key_string)
        cipher = PKCS1_OAEP.new(pub_key)
        encrypted = cipher.encrypt(message.encode())
        c.send_binary_message(do_kogo_uid, encrypted)

    

c = Client("http://127.0.0.1:5555")
c.send_signed_message("test wiadomosci", "deadbeef")

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64



def encrypt_message(message, public_key_path):
    # Load the public RSA key
    with open(public_key_path, 'rb') as key_file:
        public_key = RSA.import_key(key_file.read())

    # Create a cipher object with the public key
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the message using the public key
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
        # binary message to encrypt)


    return encrypted_message


def decrypt_message(encoded_message, private_key_path):
    # Load the private RSA key
    with open(private_key_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())

    # Create a cipher object with the private key
    cipher = PKCS1_OAEP.new(private_key)

    # # Decode the base64-encoded message
    # encrypted_message = base64.b64decode(encoded_message)

    # Decrypt the message using the private key
    decrypted_message = cipher.decrypt(encoded_message).decode('utf-8')

    return decrypted_message

john_public_key_path = "rsa_server_client\id_rsa_pub_john.pub"
john_private_key_path = "rsa_server_client\id_rsa_john"
message = "hello world"

# dodajemy klucz jako john

# jako mark bierzemy pub john
# kodujemy wiadomosc jego kluczem publicznym
# wysylamy mu zakodowana wiadomosc

# jako (john)
# sprawdzamy czy dostalismy jakas wiadomosc
# odkodowujemy ja za pomoca naszego klucza prywatnego


with open(john_public_key_path, 'rb') as key_file:
    john_public_key = RSA.import_key(key_file.read())

# jestesmy johnem
c1 = Client("http://127.0.0.1:5555")
c1.send_key("john", john_public_key.export_key())

# jestesmy markiem
c2 = Client("http://127.0.0.1:5555")
c2.send_signed_message(message, "john")

john_message = c1.get_binary_message("john")
decrypted_message = decrypt_message(john_message, john_private_key_path)
print(f"wiadomosc do johna: {decrypted_message}")







