import socket
import threading
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding


class Client:
    # init Client
    def __init__(self,phoneNumber,passcode_salt, passcode_key):
        # how to define host and port?
        self.host
        self.port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def generate_keypair(self):
        # Creating key using Diffie-hellman key exchange
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.connected = True

        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.socket.sendall(public_key_bytes)

        public_key_server_bytes = self.socket.recv(1024)
        public_key_server = serialization.load_pem_public_key(public_key_server_bytes, backend=default_backend())

        shared_key = self.private_key.exchange(public_key_server)

        thread = threading.Thread(target=self.receive_messages)
        thread.start()