import socket
import threading
import random
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from tkinter import*
clients = {}
lock = threading.Lock()
PASSWORD_TIMEOUT = 60
#RSA public and private key for the server
server_private_key = rsa.generate_private_key( public_exponent=65537, key_size=2048 )
server_public_key = server_private_key.public_key()
# Serialize public keys for sharing
server_public_pem = server_public_key.public_bytes( encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def client_handler(client_socket):
    phone_number = client_socket.recv(1024).decode().strip()
    # Adding function for password
    send_password_first_connect(client_socket)

    # Receive client's public key
    client_public_pem = client_socket.recv(4096)
    print("The PEM is: " + client_public_pem.decode())
    client_public_key = serialization.load_pem_public_key(client_public_pem)

    print("Sending the server PEM...")
    client_socket.sendall(server_public_pem)

    with lock:
        if phone_number not in clients:
            clients[phone_number] = {
                "online": True,
                "socket": client_socket,
                "offline_messages": [],
                "public key": client_public_key,
            }
            client_socket.sendall(b"REGISTERED")
            print(f"[Server] New user registered: {phone_number}")
        else:
            # The client already exists
            clients[phone_number]["online"] = True
            clients[phone_number]["socket"] = client_socket
            client_socket.sendall(b"AUTH_OK")
            print(f"[Server] Existing user reconnected: {phone_number}")

        # Send offline messages
        if clients[phone_number]["offline_messages"]:
            print(
                f"[Server] Sending {len(clients[phone_number]['offline_messages'])} offline messages to {phone_number}")
        for msg in clients[phone_number]["offline_messages"]:
            from_num, message = msg
            data_to_send = f"MSG:{from_num}:{message}".encode()
            client_socket.sendall(data_to_send)
        clients[phone_number]["offline_messages"].clear()

    while True:
        try:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                # Disconnecting
                with lock:
                    clients[phone_number]["online"] = False
                    clients[phone_number]["socket"] = None
                print(f"[Server] User {phone_number} disconnected.")
                break

            # Decrypt the received data
            data = server_private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            message = data.decode()
            print(f"[Server] Decrypted message: {message}")

            # Handle the SEND command
            parts = message.split(":", 2)
            if parts[0] == "SEND":
                target_phone = parts[1]
                message = parts[2] if len(parts) > 2 else ""
                with lock:
                    if target_phone in clients:
                        if clients[target_phone]["online"]:
                            target_socket = clients[target_phone]["socket"]
                            target_public_key = clients[target_phone]["public key"]
                            # Encrypt the message with the target's public key
                            data_to_send = target_public_key.encrypt(
                                f"MSG:{phone_number}:{message}".encode(),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                            target_socket.sendall(data_to_send)
                            # Wait for ACK
                            ack = target_socket.recv(1024)
                            client_socket.sendall(b"ACK_RECEIVED_BY_TARGET")
                            print(f"[Server] Message delivered immediately from {phone_number} to {target_phone}")
                        else:
                            # Saving for offline delivery
                            clients[target_phone]["offline_messages"].append((phone_number, message))
                            client_socket.sendall(b"OFFLINE_STORED")
                            print(f"[Server] Message from {phone_number} to {target_phone} stored offline.")
                    else:
                        client_socket.sendall(b"ERROR_UNKNOWN_TARGET")
                        print(f"[Server] Attempt to send to unknown target {target_phone} by {phone_number}")

        except Exception as e:
            print(f"[Server] Error: {e}")
            with lock:
                clients[phone_number]["online"] = False
                clients[phone_number]["socket"] = None
            break


def run_server():
    host = '127.0.0.1'
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[Server] Listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[Server] Client connected: {addr}")
        threading.Thread(target=client_handler, args=(client_socket,)).start()

#Function for sending password for validate
def send_password_first_connect(client_socket):
    print("Check your computer for a 6-digit password")
    password = random.randint(100000, 999999)
    client_socket.sendall(f"PASSWORD:{password}".encode())
    print(f"[Server] Sent password {password} to client.")
    # Timer to track password timeout
    while True:
        try:
            client_socket.settimeout(PASSWORD_TIMEOUT)
            client_password = client_socket.recv(1024).decode().strip()
            if client_password == str(password):
                client_socket.sendall(b"AUTH_SUCCESS")
                print(f"[Server] Client successfully authenticated.")
                client_socket.settimeout(None)
                break
            else:
                client_socket.sendall(b"ERROR:INVALID_PASSWORD")
                print(f"[Server] Client entered an incorrect password.")
        except socket.timeout:
                print("[Server] Password authentication timed out for client.")
                client_socket.sendall(b"ERROR:PASSWORD_TIMEOUT")
                client_socket.close()
        except Exception as e:
            print(f"[Server] Error during password authentication: {e}")
            client_socket.sendall(b"ERROR:SERVER_ERROR")
            client_socket.close()


if __name__ == "__main__":
    run_server()
