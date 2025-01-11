"""
This file contains the server implementations for a secure end-to-end communication system using
cryptographic techniques like Elliptic Curve Diffie-Hellman (ECDH) and Advanced Encryption Standard (AES).
"""

import json
import socket
import threading
import datetime
import time
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, padding
from base64 import b64encode


# Global Variables
clients = {}  # Stores client data
phone_to_client_id = {}  # Maps phone numbers to client IDs
public_keys = {}  # Maps phone numbers to public keys
lock = threading.Lock()  # Ensures thread safety and avoiding race condition
LIMIT_CLIENTS = 10  # Maximum allowed clients
LIMIT_OFFLINE_MESSAGES = 2  # Maximum offline messages stored per client


def get_timestamp():
    """
    Get the current timestamp.
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def generate_random_6_digit_for_validation():
    """
    Generate a random 6-digit verification code.
    """
    return random.randint(100000, 999999)


def SendBySecureChannel(client_socket, verification_code):
    """
    Send a verification code to the client using a secured channel. The name is the same as requested in
    the project demands.
    :param client_socket: the socket of the client we want to send verification code to
    :param verification_code: the verification code we generated
    """
    client_socket.sendall(f"Verification code: {verification_code}".encode())


def save_public_key(phone_number, public_key_bytes):
    """
    Save the public key for a client, identified by phone number.
    """
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    with lock:
        public_keys[phone_number] = public_key
    print(f"[Server {get_timestamp()}] Saved public key for {phone_number}.")


def sign_data(private_key, data):
    """
    Sign data with the server's EC private key using ECDSA.
    :param private_key: the server's private key
    :param data: data to sign (bytes)
    :return: base64 encoded signature
    """
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return b64encode(signature).decode()


def get_public_key(phone_number):
    """
    Get the public key for a client, identified by phone number.
    :param phone_number: the phone number of the client we want to talk to
    """
    with lock:
        public_key = public_keys.get(phone_number)
        if public_key:
            return public_key
        else:
            print(f"[Server {get_timestamp()}] Public key for {phone_number} not found.")
            return None


def generate_ec_keypair():
    """
    Generate an Elliptic Curve (EC) key pair for ECDH.
    :return: private_key, public_key
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


class ClientHandler:
    """
    This class handles the client communications.
    """

    def __init__(self, client_socket, phone_number, server_private_key):
        """
        Handles communication and operations for a connected client.
        :param client_socket: the client's socket
        :param phone_number: the client's phone number
        :param server_private_key: The server's private key for cryptographic operations
        """
        self.client_socket = client_socket
        self.phone_number = phone_number
        self.server_private_key = server_private_key
        self.client_public_key = None
        self.symmetric_key = None
        self.private_key, self.public_key = generate_ec_keypair()
        self.boolean_online = True
        self.offline_messages = []
        self.current_offline_messages = 0

        threading.Thread(target=self.simulate_status, daemon=True).start()

    def simulate_status(self):
        """
        Simulate client going online/offline without actual disconnection in order to avoid memory loss
        """
        while True:
            time.sleep(45)
            self.boolean_online = not self.boolean_online
            if self.boolean_online:
                self.handling_offline_messages()
            status = "online" if self.boolean_online else "offline"
            print(f"[Server {get_timestamp()}] Client {self.phone_number} is now {status}")

    def handle(self):
        """
        Main loop for handling incoming messages and requests from the client.
        """
        try:
            # Receive client's public key
            client_public_key_bytes = self.client_socket.recv(4096)
            if not client_public_key_bytes:
                print(f"[Server {get_timestamp()}] No public key received from {self.phone_number}.")
                return

            # Save the client's public key
            save_public_key(self.phone_number, client_public_key_bytes)

            # Send the server's public key to the client
            server_public_key_bytes = self.server_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.client_socket.sendall(server_public_key_bytes)
            print(f"[Server {get_timestamp()}] Sent server public key to {self.phone_number}.")
        except Exception as e:
            print(f"[Server {get_timestamp()}] Error handling client {self.phone_number}: {e}")
            import traceback
            traceback.print_exc()

        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                try:
                    message = data.decode('utf-8')
                except UnicodeDecodeError:
                    print(f"[Server {get_timestamp()}] Decoding error: {data}")
                    continue

                if message.startswith("CHAT_REQUEST:"):
                    target_phone = message.split(":")[1].strip()
                    self.initiate_chat(target_phone)
                elif message.startswith("MESSAGE:"):
                    try:
                        data = json.loads(message[8:])
                        # Extract key data from data
                        target_phone = data.get('target')
                        sender_phone = data.get('sender')
                        signature = data.get('signature', '')
                        client_timestamp = data.get('client_timestamp')
                        message_data = data.get('encrypted_data')
                        iv = message_data['iv']
                        ciphertext = message_data['ciphertext']
                        if target_phone not in phone_to_client_id:
                            self.client_socket.sendall(f"{target_phone} INVALID CLIENT!")
                            continue
                        # Add server timestamp
                        data['server_timestamp'] = get_timestamp()

                        message_data = {
                            'iv': iv,
                            'ciphertext': ciphertext
                        }

                        # Forward the message
                        self.forward_message({
                            'target': target_phone,
                            'sender': sender_phone,
                            'server_timestamp': data['server_timestamp'],
                            'client_timestamp': client_timestamp,
                            'encrypted_data': message_data,
                            'signature': signature
                        })
                    except json.JSONDecodeError as json_error:
                        # Print the error
                        print(f"[Server {get_timestamp()}] JSON Decode Error: {json_error}")
                        print(f"[Server {get_timestamp()}] Problematic Message: {message}")

            except Exception as e:
                print(f"[Server {get_timestamp()}] Error handling client {self.phone_number}: {e}")
                import traceback
                traceback.print_exc()
                break

    def initiate_chat(self, target_phone):
        """
        Initiate a secure chat session between the client and the target phone.
        :param target_phone: the phone number of the client we want to talk with
        """
        with lock:
            if target_phone not in phone_to_client_id:
                print(
                    f"[Server {get_timestamp()}] {self.phone_number} tried to initiate chat"
                    f" with unregistered target {target_phone}.")
                self.client_socket.sendall(b"ERROR:TARGET_NOT_FOUND")
                return

            target_id = phone_to_client_id[target_phone]
            target = clients[target_id]

        try:
            self.client_socket.sendall(b"START_ECDH")

            target_public_key_bytes = get_public_key(target_phone).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            target_signature = sign_data(self.server_private_key, target_public_key_bytes)

            payload_initiator = json.dumps({
                "public_key": target_public_key_bytes.decode('utf-8'),
                "signature": target_signature
            }).encode('utf-8')

            self.client_socket.sendall(payload_initiator)

            target.client_socket.sendall(b"START_ECDH")

            initiator_public_key_bytes = get_public_key(self.phone_number).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            initiator_signature = sign_data(self.server_private_key, initiator_public_key_bytes)

            payload_target = json.dumps({
                "public_key": initiator_public_key_bytes.decode('utf-8'),
                "signature": initiator_signature
            }).encode('utf-8')

            # Send the signed public key to the target
            target.client_socket.sendall(payload_target)

            # Forward salt and phone number
            salt_encrypted = self.client_socket.recv(16)
            target.client_socket.sendall(salt_encrypted)

            phone_number = self.client_socket.recv(16)
            target.client_socket.sendall(phone_number)

            print(f"[Server {get_timestamp()}] Secure chat established between {self.phone_number} and {target_phone}")
            self.client_socket.sendall(b"TEST")

        except Exception as e:
            print(f"[Server {get_timestamp()}] Error during ECDH exchange: {e}")
            self.client_socket.sendall(b"ERROR: Failed to complete the ECDH exchange")

    def forward_message(self, payload):
        """
        Handle and forward an encrypted message from the client.
        :param payload: The raw message payload from the client
        """
        with lock:
            target_phone = payload["target"]
            if target_phone not in phone_to_client_id:
                print(f"[Server {get_timestamp()}] Target phone {target_phone} not registered.")
                return
            sender_id = phone_to_client_id[payload['sender']]
            sender = clients[sender_id]
            target_id = phone_to_client_id[target_phone]
            target = clients[target_id]
            # Check if the target is online
            if not target.boolean_online:
                print(f"[Server {get_timestamp()}] Target phone {target_phone} is offline. Saving message in Server.")
                if self.current_offline_messages == LIMIT_OFFLINE_MESSAGES:
                    # Sending error to sender
                    sender.client_socket.sendall(
                        f"[Server {get_timestamp()}] ERROR: too many offline messages for client {target_phone}."
                        f" Try again later".encode())
                target.offline_messages.append(payload)
                self.current_offline_messages = self.current_offline_messages + 1
                return

        try:
            target.client_socket.sendall(f"MESSAGE:{json.dumps(payload)}".encode())
            # Send ACK back to sender
            sender.client_socket.sendall(f"ACK{target_phone}".encode())
            print(f"[Server {get_timestamp()}] Message forwarded from {self.phone_number} to {target_phone}")
        except Exception as e:
            print(f"[Server {get_timestamp()}] Error forwarding message to {target_phone}: {e}")

    def handling_offline_messages(self):
        """
        Deliver any stored offline messages to the client when they come online.
        """
        if not self.offline_messages:
            return
        print(f"[Server {get_timestamp()}] Delivering offline messages to {self.phone_number}.")
        try:
            while self.offline_messages:
                payload = self.offline_messages.pop()
                # Send the offline message to the client
                self.current_offline_messages = -1
                self.forward_message(payload)
            # Clear the offline messages after successful delivery
            self.offline_messages.clear()

        except Exception as e:
            print(f"[Server {get_timestamp()}] Error delivering offline messages to {self.phone_number}: {e}")
        finally:
            return


class Server:
    """
    Represents the server that manages client connections and communication.
    """

    def __init__(self, host='127.0.0.1', port=12345):
        """
        initiating the server
        :param host: local host
        :param port: random port number we chose to communicate with
        """
        self.host = host
        self.port = port
        self.server_private_key, self.server_public_key = generate_ec_keypair()

    def start(self):
        """
        Start the server and listen for incoming client connections.
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"[Server {get_timestamp()}] Listening on {self.host}:{self.port}")

        # Handle client registration and spawn ClientHandler threads
        while True:
            client_socket, addr = server_socket.accept()
            phone_number = client_socket.recv(1024).decode().strip()

            if not phone_number:
                client_socket.close()
                continue

            with lock:
                if phone_number in phone_to_client_id:
                    client_socket.sendall(b"ERROR:PHONE_ALREADY_REGISTERED")
                    client_socket.close()
                    continue
                if len(phone_number) != 10 or not phone_number.isdigit():
                    client_socket.sendall(b"ERROR:INVALID PHONE NUMBER")
                    client_socket.close()
                if len(phone_to_client_id) > LIMIT_CLIENTS - 1:
                    print("[Server] Too many clients registered.")
                    client_socket.sendall(b"TOO MANY CLIENTS REGISTERED! TRY AGAIN LATER.")
                    client_socket.close()
                    continue
                verification_code = generate_random_6_digit_for_validation()
                SendBySecureChannel(client_socket, verification_code)
                start_time = time.time()
                print(f"[Server {get_timestamp()}] Sent verification code {verification_code} to {phone_number}")
                response = client_socket.recv(1024).decode().strip()
                end_time = time.time()
                if response != str(verification_code):
                    print("[Server] Entered invalid verification code. ")
                    client_socket.sendall(b"ERROR:INVALID VERIFICATION CODE")
                    client_socket.close()
                    continue
                if response == str(verification_code):
                    if end_time - start_time > 100:  # Making sure we are getting response in under a minute and a half
                        print("[Server] Time out for verification. ")
                        client_socket.sendall(b"Error: Timed out.")
                        client_socket.close()
                        return False, None
                client_id = len(clients) + 1
                handler = ClientHandler(client_socket, phone_number, self.server_private_key)
                clients[client_id] = handler
                phone_to_client_id[phone_number] = client_id
                print(f"[Server {get_timestamp()}] Registered client {phone_number} with ID {client_id}")

            client_socket.sendall(b"AUTH_SUCCESS")
            threading.Thread(target=handler.handle, daemon=True).start()


if __name__ == "__main__":
    server = Server()
    server.start()
