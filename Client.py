"""
This file contains the client implementations for a secure end-to-end communication system using
cryptographic techniques like Elliptic Curve Diffie-Hellman (ECDH) and Advanced Encryption Standard (AES).
"""

import os
import json
import socket
import threading
import datetime
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def get_timestamp():
    """
    Get the current timestamp.
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def generate_ec_keypair():
    """
    Generate an Elliptic Curve (EC) key pair for ECDH.
    :return: private_key, public_key
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    print(f"[Client] {get_timestamp()}] Generated Private Key:", private_key.private_numbers().private_value)
    print(f"[Client {get_timestamp()}] Generated Public Key:",
          public_key.public_numbers().x,
          public_key.public_numbers().y)
    return private_key, public_key

def create_shared_secret(private_key, peer_public_key):
    """
    Creating shared secret between the client and the target
    :param private_key: the client's private key
    :param peer_public_key: the target's public key
    :return: the shared secret
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    print(f"[Client {get_timestamp()}] Shared Secret:", shared_secret.hex())
    return shared_secret

def derive_key(shared_secret, salt):
    """
    Derive a key using the shared secret and random salt value to increase security
    :param shared_secret: the shared secret between the two clients
    :param salt: the random value we chose as salt
    :return: the key
    """
    print(f"[Client {get_timestamp()}] Salt for Key Derivation:", salt.hex())
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"e2e-encryption",
        backend=default_backend()
    ).derive(shared_secret)
    print(f"[Client {get_timestamp()}] Derived Symmetric Key:", derived_key.hex())
    return derived_key

def aes_encrypt(data, key):
    """
    Encrypts data using AES
    :param data: the data we want to encrypt
    :param key: the shared key between the two clients
    :return: the encrypted data
    """
    print(f"[Client {get_timestamp()}] Plaintext to Encrypt:", data)
    iv = os.urandom(16)
    print(f"[Client {get_timestamp()}] Generated IV:", iv.hex())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"[Client {get_timestamp()}] Encrypted Ciphertext:", ciphertext.hex())
    return {
        "iv": b64encode(iv).decode(),
        "ciphertext": b64encode(ciphertext).decode()
    }

def aes_decrypt(ciphertext, key, iv):
    """
    Decrypts data using AES
    :param ciphertext: the encrypted data
    :param key: the shared key between the two clients
    :param iv: the iv value we used
    :return: plaintext we can read
    """
    print(f"[Client {get_timestamp()}] Received IV:", iv)
    print(f"[Client {get_timestamp()}] Received Ciphertext:", ciphertext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(b64decode(ciphertext)) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    print(f"[Client {get_timestamp()}] Decrypted Plaintext:", plaintext.decode())
    return plaintext

def sign_data(private_key, data):
    """
    Sign data with an EC private key using ECDSA so the recipient will know it's from us
    :param private_key: the client's private key
    :param data: the data we want to sign
    :return: base64 encoded signature
    """
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return b64encode(signature).decode()


def verify_server_signature(server_public_key, public_key_bytes, signature):
    """
    Verify the signature of the server using its public key.
    :param server_public_key: the public key of the server
    :param public_key_bytes: the public key of the server in bytes
    :param signature: the signature we want to verify
    :return: true if it's the server's signature, false otherwise
    """
    try:
        decoded_signature = b64decode(signature)
        server_public_key.verify(
            decoded_signature,
            public_key_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


def verify_signature(public_key_pem, data, signature):
    """
    Verify the signature of the data using an EC public key.
    :param public_key_pem: the public key of the sender
    :param data: the data we want to check its signature
    :param signature: the signature we are verifying
    :return: base64 encoded signature
    """
    try:
        # Load the PEM-encoded public key back into a key object
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Decode the base64 signature
        decoded_signature = b64decode(signature)

        public_key.verify(
            decoded_signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

class Client:
    """
    This class handles the client communication
    """
    def __init__(self, phone_number):
        """
        Initiating the clients data
        :param phone_number: the client's phone number
        """
        self.phone_number = phone_number
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_ec_keypair()
        self.server_public_key = None
        self.connected = False
        self.ecdh_event = threading.Event()
        self.current_target_phone = None
        self.lock = threading.Lock()
        self.client_data = {}
        self.command_ready = threading.Event()
        self.waiting_for_ack = {}

    def connect(self, host='127.0.0.1', port=12345):
        """
        Connecting and registering the client to the server
        :param host: local host
        :param port: the port number we are working on
        """
        try:
            self.socket.connect((host, port))
            connect_time = get_timestamp()
            self.socket.sendall(self.phone_number.encode())
            response = self.socket.recv(1024).decode()
            if response.startswith("Verification code:"):
                print(response)
                code = input("Enter the verification code: ").strip()
                self.socket.sendall(code.encode())  # Send the code back to the server

                response = self.socket.recv(1024).decode()
                if response == "AUTH_SUCCESS":
                    print(f"[Client {connect_time}] Authentication successful!")
                    self.socket.sendall(self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    server_pubkey_bytes = self.socket.recv(4096)
                    self.server_public_key = serialization.load_pem_public_key(
                        server_pubkey_bytes,
                        backend=default_backend()
                    )

                    self.connected = True
                    threading.Thread(target=self.receive_messages, daemon=True).start()
                    return True
                else:
                    print(f"[Client {get_timestamp()}] Registration failed: {response}")
                    return False
            else:
                print(f"[Client {get_timestamp()}] Unexpected response: {response}")
                return False
        except Exception as e:
            print(f"[Client {get_timestamp()}] Connection error: {e}")
            return False


    def initiate_chat(self, target_phone):
        """
        Initiating the client chat with the target client
        :param target_phone: the phone number of the target client
        :return: true if we managed to establish the connection, false otherwise
        """
        if not self.connected:
            print(f"[Client {get_timestamp()}] Not connected to the server.")
            return False

        self.ecdh_event.clear()
        self.current_target_phone = target_phone
        self.socket.sendall(f"CHAT_REQUEST:{target_phone}".encode())
        self._handle_ecdh_start()

        if self.ecdh_event.wait(timeout=30):
            self.command_ready.set()
            return True
        else:
            print(f"[Client {get_timestamp()}] ECDH handshake timed out.")
            self.command_ready.set()
            return False

    def _handle_ecdh_start(self):
        """
        Handling the ECDH handshake as initiator with server-signed public key verification.
        """
        try:
            peer_data_raw = self.socket.recv(4096).decode()

            if not peer_data_raw.strip():  # Check for empty or whitespace-only responses
                print(f"[Client {get_timestamp()}] No data received from the server during ECDH.")
                self.ecdh_event.set()
                return

            try:
                peer_data = json.loads(peer_data_raw)

            except json.JSONDecodeError as e:
                print(f"[Client {get_timestamp()}] JSON Decode Error: {e}")
                print(f"[Client {get_timestamp()}] Raw data received: {peer_data_raw}")
                self.ecdh_event.set()
                return

            peer_public_key_bytes = peer_data["public_key"].encode()
            server_signature = peer_data["signature"]

            if not verify_server_signature(self.server_public_key, peer_public_key_bytes, server_signature):
                print(f"[Client {get_timestamp()}] Server signature verification failed for peer public key")
                self.ecdh_event.set()
                return

            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_bytes,
                backend=default_backend()
            )

            shared_secret = create_shared_secret(self.private_key, peer_public_key)
            salt = os.urandom(16)
            self.socket.sendall(salt)
            self.socket.sendall(self.phone_number.encode())

            derived_key = derive_key(shared_secret, salt)
            self.save_client_data(self.current_target_phone, shared_secret, salt, derived_key, peer_public_key)

            self.ecdh_event.set()
            print(f"[Client {get_timestamp()}] Secure communication established.")

        except Exception as e:
            print(f"[Client {get_timestamp()}] ECDH Error: {e}")
            self.ecdh_event.set()

    def handle_ecdh_receive(self):
        """
        Handling the ECDH handshake as receiver.
        """
        if self.connected:
            try:
                    peer_data_raw = self.socket.recv(4096).decode()
                    if not peer_data_raw:
                        print(f"[Client {get_timestamp()}] No data received from the server.")
                        self.ecdh_event.set()
                        return

                    if peer_data_raw == "TEST":
                        return

                    if peer_data_raw.startswith("ACK"):
                        return

                    try:
                        peer_data = json.loads(peer_data_raw)
                    except json.JSONDecodeError as e:
                        print(f"[Client {get_timestamp()}] JSON Decode Error: {e}")
                        print(f"[Client {get_timestamp()}] Raw data received: {peer_data_raw}")
                        self.ecdh_event.set()
                        return

                    peer_public_key_bytes = peer_data["public_key"].encode()
                    server_signature = peer_data["signature"]

                    # Verify the server's signature
                    if not verify_server_signature(self.server_public_key, peer_public_key_bytes, server_signature):
                        print(f"[Client {get_timestamp()}] Server signature verification failed for peer public key")
                        self.ecdh_event.set()
                        return

                    peer_public_key = serialization.load_pem_public_key(
                        peer_public_key_bytes,
                        backend=default_backend()
                    )

                    # Proceed with ECDH key exchange
                    shared_secret = create_shared_secret(self.private_key, peer_public_key)
                    salt = self.socket.recv(16)
                    self.current_target_phone = self.socket.recv(16).decode()
                    derived_key = derive_key(shared_secret, salt)

                    self.save_client_data(self.current_target_phone, shared_secret, salt, derived_key, peer_public_key)
                    print(f"[Client {get_timestamp()}] Secure communication established.")
                    self.ecdh_event.set()

            except Exception as e:
                print(f"[Client {get_timestamp()}] ECDH Error: {e}")
                self.ecdh_event.set()

    def save_client_data(self, target_phone, shared_secret, salt, derived_key, peer_public_key):
        """
        Save the target client data so we can communicate with him/her
        :param target_phone: the target client's phone number
        :param shared_secret: the shared secret between the client and the target
        :param salt: the salt of the client and the target
        :param derived_key: the shared key between the client and the target
        :param peer_public_key: the public key of the target client
        """
        self.client_data[target_phone] = {
            "shared_secret": shared_secret.hex(),
            "salt": salt.hex(),
            "derived_key": derived_key.hex(),
            "public_key": peer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

    def send_message(self, target_phone, message):
        """
        Send a message to the target phone
        :param target_phone: the phone number of the target client
        :param message: the message we want to send
        """
        if not self.connected:
            print(f"[Client {get_timestamp()}] Not connected to the server.")
            return

        client_data = self.client_data.get(target_phone)
        if not client_data:
            print(f"[Client {get_timestamp()}] No encryption keys found for {target_phone}. Initiate chat first.")
            return

        try:
            # Derive the symmetric key
            symmetric_key = bytes.fromhex(client_data['derived_key'])

            # Encrypt the message
            encrypted_data = aes_encrypt(message.encode(), symmetric_key)

            # Create a dictionary of the data to be signed
            message_data = {
                "iv": encrypted_data["iv"],
                "ciphertext": encrypted_data["ciphertext"]
            }

            # Sign the message data
            signature = sign_data(self.private_key, json.dumps(message_data).encode())

            # Prepare the payload
            payload = {
                "target": target_phone,
                "sender": self.phone_number,
                "client_timestamp": get_timestamp(),
                "encrypted_data": message_data,  # Now includes both iv and ciphertext
                "signature": signature
            }

            # Send the payload to the server
            self.socket.sendall(f"MESSAGE:{json.dumps(payload)}".encode())
            self.waiting_for_ack[target_phone] = True
            print(f"[Client {get_timestamp()}] Encrypted message sent.")

        except Exception as e:
            print(f"[Client {get_timestamp()}] Error sending message: {e}")

    def receive_messages(self):
        """
        Receive messages from the target phone
        """
        while self.connected:
            try:
                self.socket.sendall(b"RECONNECT")
                data = self.socket.recv(4096)
                if not data:
                    break
                message = data.decode()
                if message.startswith("TEST"):
                    continue
                if message.startswith("START_ECDH"):
                    self.handle_ecdh_receive()
                    continue
                if message.startswith("ACK"):
                    phone_ack = message[3:]
                    if self.waiting_for_ack.get(phone_ack):
                        print(f"[Client {get_timestamp()}] Message delivery confirmed for {phone_ack}")
                        del self.waiting_for_ack[phone_ack]
                        continue
                if message.startswith("MESSAGE:"):
                    try:
                        payload = json.loads(message[8:])
                        sender = payload.get('sender', 'Unknown')
                        client_data = self.client_data.get(sender)

                        if not client_data:
                            print(f"[Client {get_timestamp()}] No encryption keys found for sender {sender}")
                            continue

                        if 'signature' not in payload:
                            print(f"[Client {get_timestamp()}] Signature missing from payload: {payload}")
                            continue

                        encrypted_data = payload.get('encrypted_data', {})
                        if not encrypted_data or not encrypted_data.get('iv') or not encrypted_data.get('ciphertext'):
                            print(f"[Client {get_timestamp()}] Encrypted payload is invalid: {encrypted_data}")
                            continue

                        # Verify signature
                        if not verify_signature(
                                client_data['public_key'],
                                json.dumps(encrypted_data).encode(),
                                payload['signature']
                        ):
                            print(f"[Client {get_timestamp()}] Invalid signature from {sender}. Message dropped.")
                            continue
                        else:
                            print(f"[Client {get_timestamp()}] valid signature from {sender}")

                        # Decrypt message
                        symmetric_key = bytes.fromhex(client_data['derived_key'])
                        plaintext = aes_decrypt(
                            encrypted_data['ciphertext'],
                            symmetric_key,
                            encrypted_data['iv']
                        )

                        print(f"[{get_timestamp()} Message from {sender}] {plaintext.decode('utf-8')}")
                        print("Enter command (chat <phone>, send <phone> <message>, quit):")

                    except json.JSONDecodeError as e:
                        print(f"[Client {get_timestamp()}] JSON parsing error: {e}")
                    except Exception as e:
                        print(f"[Client {get_timestamp()}] Message decryption error: {e}")
                else:
                    print(f"[Client {get_timestamp()}] Server message: {message}")
                    print("Enter command (chat <phone>, send <phone> <message>, quit):")

            except Exception as e:
                print(f"[Client {get_timestamp()}] Error receiving message: {e}")
                break


    def disconnect(self):
        """
        Disconnect the client from the server
        """
        try:
            self.connected = False
            self.socket.close()
            print(f"[Client {get_timestamp()}] Disconnected.")
        except Exception as e:
            print(f"[Client {get_timestamp()}] Error during disconnection: {e}")

def main():
    """
    Main function
    """
    phone_number = input("Welcome to FriendLy! Please enter your phone number: ")
    client = Client(phone_number)

    if not client.connect():
        return
    while client.connected:
        try:
            # If we want to start a conversation we need to first choose chat <phone> and only then send messages
            print("Enter command (chat <phone>, send <phone> <message>, quit):")
            command = input("").strip()

            if command == "quit":
                client.disconnect()
                break

            elif command.startswith("chat"):
                try:
                    _, target = command.split(maxsplit=1)
                    client.command_ready.clear()
                    client.initiate_chat(target)
                    client.command_ready.wait()  # Wait for chat initialization to complete
                except ValueError:
                    print(f"[Client {get_timestamp()}] Invalid chat command. Use 'chat <phone>'")

            elif command.startswith("send"):
                try:
                    _, target, message = command.split(maxsplit=2)
                    client.send_message(target, message)
                except ValueError:
                    print(f"[Client {get_timestamp()}] Invalid send command. Use 'send <phone> <message>'")

            else:
                print(f"[Client {get_timestamp()}] Unknown command.")

        except KeyboardInterrupt:
            print(f"[Client {get_timestamp()}] Exiting...")
            client.disconnect()
            break

if __name__ == "__main__":
    main()
