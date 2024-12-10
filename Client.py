# from cryptography.hazmat.primitives.asymmetric import rsa
#from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#from cryptography.hazmat.primitives import hashes, serialization
#from cryptography.hazmat.backends import default_backend
#import os
#import socket
#import threading
import sys
#import random

import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class Client:
    def __init__(self, phone_numb):
        # Generate RSA key pair for client
        self.client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.client_public_key = self.client_private_key.public_key()
        # Serialize public keys for sharing
        self.client_public_pem = self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.phone_number = phone_numb
        self.host = '127.0.0.1'
        self.port = 12345
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.socket.sendall(self.phone_number.encode())
        while True:
            resp = self.socket.recv(1024).decode()
            if resp.startswith("PASSWORD:"):
                password = resp.split(":")[1]
                print(f"[Client] Received password {password}.")
                password_input = input("Enter the password: ")
                self.socket.sendall(password_input.encode())  # Send the password back
            elif resp == "AUTH_SUCCESS":
                print("[Client] Authentication successful!\n Getting pem...")
                self.socket.sendall(self.client_public_pem)
                server_public_pem = self.socket.recv(4096)
                self.server_public_key = serialization.load_pem_public_key(server_public_pem)
                print("the pem is: " + server_public_pem.decode())
                self.connected = True
                break
            elif resp.startswith("ERROR"):
                print(f"[Client] Authentication failed: {resp}")
                self.socket.close()
                return
            else:
                print("[Client] Unexpected response during connection:", resp)
                self.socket.close()
                return

        if self.connected:
            threading.Thread(target=self.receive_messages, daemon=True).start()
            print("[Client] You can now send messages using 'send <target> <message>' or type 'quit' to exit.")
            print("end of connect def")

    def send_message(self, target_phone, message):
        data = f"SEND:{target_phone}:{message}".encode()
        encrypted_data = self.server_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(encrypted_data)
        self.socket.sendall(encrypted_data)
        ack = self.socket.recv(1024)
        print("[Client] Server response:", ack.decode())

    def receive_messages(self):
        while self.connected:
            try:
                encrypted_data = b""
                while len(encrypted_data) < 256:  # Ensure the full RSA block is received
                    chunk = self.socket.recv(256 - len(encrypted_data))
                    if not chunk:
                        print("[Client] Connection closed by server.")
                        self.disconnect()
                        return
                    encrypted_data += chunk

                # Decrypt the received message
                data = self.client_private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # Process the decrypted message
                if data.startswith(b"MSG:"):
                    parts = data.decode().split(":", 2)
                    from_num = parts[1]
                    msg = parts[2]
                    print(f"\n[Client] Message from {from_num}: {msg}")
                    self.socket.sendall(b"ACK")
                    print("[Client] You received a message. You can still send messages or type 'quit' to exit.")
            except Exception as e:
                print(f"[Client] Error while receiving message: {e}")
                self.disconnect()
                break

    def disconnect(self):
        self.socket.close()
        self.connected = False
        print("[Client] Disconnected.")

if __name__ == "__main__":
    phone_number = input("Enter your phone number: ")
    c = Client(phone_number)
    c.connect()

    while c.connected:
        cmd = input("Enter command (send <target> <message>, or quit): ")
        if cmd.strip().lower() == "quit":
            c.disconnect()
            break
        parts = cmd.split(" ",2)
        if len(parts) >= 2 and parts[0] == "send":
            if len(parts) == 3:
                target = parts[1]
                msg = parts[2]
            else:
                target = parts[1]
                msg = ""
            c.send_message(target, msg)
        else:
            print("[Client] Unknown command. Use 'send <target> <message>' or 'quit'.")


