# Import necessary libraries
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad
import socket


# AES Encryption and Decryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)  # Add padding
    return cipher.encrypt(padded_data)


def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)  # Remove padding


# SHA256 Hashing
def sha256_hash(data):
    hash_object = SHA256.new(data)
    return hash_object.digest()


# RSA Key Generation, Encryption, and Decryption
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()


def rsa_encrypt(data, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(data)


def rsa_decrypt(ciphertext, private_key):
    recipient_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.decrypt(ciphertext)


# Diffie-Hellman Key Exchange
class DiffieHellman:
    def __init__(self, bit_length):
        self.p = getPrime(bit_length, get_random_bytes)
        self.g = 2  # primitive root modulo
        self.a = int.from_bytes(get_random_bytes(32), byteorder='big')  # private key
        self.public_key = pow(self.g, self.a, self.p)

    def compute_shared_secret(self, other_public_key):
        return pow(other_public_key, self.a, self.p)


# PKI (Public Key Infrastructure)
class PKI:
    @staticmethod
    def sign_certificate(data, private_key):
        key = RSA.import_key(private_key)
        h = SHA256.new(data)
        signature = pkcs1_15.new(key).sign(h)
        return signature

    @staticmethod
    def verify_certificate(data, signature, public_key):
        key = RSA.import_key(public_key)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


# Client-Server Architecture
class Server:
    def __init__(self, host, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)

    def accept_client(self):
        client_socket, addr = self.server_socket.accept()
        return client_socket, addr


class Client:
    def __init__(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

    def send_data(self, data):
        self.client_socket.sendall(data)

    def receive_data(self, buffer_size=1024):
        return self.client_socket.recv(buffer_size)


# Handshake Protocol
def handshake(client_public_key, server_dh):
    shared_secret = server_dh.compute_shared_secret(client_public_key)
    aes_key = SHA256.new(str(shared_secret).encode()).digest()
    return aes_key


# Main function to test the implementation

if __name__ == "__main__":
    # Test AES Encryption and Decryption
    key = b'Sixteen byte key'  # Example 128-bit key
    data = b'Hello, World!' + b' ' * 4  # Data must be a multiple of 16 bytes for AES.MODE_ECB
    encrypted_data = aes_encrypt(data, key)
    decrypted_data = aes_decrypt(encrypted_data, key)
    print(f"AES Original Data: {data}")
    print(f"AES Encrypted Data: {encrypted_data}")
    print(f"AES Decrypted Data: {decrypted_data}")
    print("-" * 50)

    # Test SHA256 Hashing
    hashed_data = sha256_hash(data)
    print(f"SHA256 Hash of {data}: {hashed_data}")
    print("-" * 50)

    # Test RSA Encryption and Decryption
    rsa_encrypted_data = rsa_encrypt(data, public_key)
    rsa_decrypted_data = rsa_decrypt(rsa_encrypted_data, private_key)
    print(f"RSA Original Data: {data}")
    print(f"RSA Encrypted Data: {rsa_encrypted_data}")
    print(f"RSA Decrypted Data: {rsa_decrypted_data}")
    print("-" * 50)

    # Test Diffie-Hellman Key Exchange
    alice = DiffieHellman(2048)
    bob = DiffieHellman(2048)
    alice_shared_secret = alice.compute_shared_secret(bob.public_key)
    bob_shared_secret = bob.compute_shared_secret(alice.public_key)
    print(f"Alice's Shared Secret: {alice_shared_secret}")
    print(f"Bob's Shared Secret: {bob_shared_secret}")
    print("-" * 50)

    # Test PKI Certificate Signing and Verification
    certificate_data = b'Example Certificate Data'
    signature = PKI.sign_certificate(certificate_data, private_key)
    is_verified = PKI.verify_certificate(certificate_data, signature, public_key)
    print(f"Certificate Data: {certificate_data}")
    print(f"Signature: {signature}")
    print(f"Verification Result: {is_verified}")
    print("-" * 50)
