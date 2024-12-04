import re
from Client import Client
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
EllipticCurvePrivateKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
#Global veribles
registered_phone_numbers = set()
def main():
    print("Welcome to friendly!")
    while True:
        phone_number = input("Please enter your phone number: ")
        if not validate_phone_number(phone_number):
            print("Invalid phone number. Make sure it is exactly 10 digits.")
            continue
        # registering the phone number and validating the phone using OTP (fake)
        otp_code = "12345"
        if register_phone_number(phone_number) and SendBySecureChannel(phone_number) == otp_code :
            client_key, client_salt =  register_passcode()
            # need to be send to the server
            registered_phone_numbers.add(Client(phone_number, client_salt, client_key))
            print("Phone number registered successfully!")
            break
        else:
            print("Phone number already exists. Please try again.")
def validate_phone_number(phone_number):
    # Check if the phone number is exactly 10 digits
    return re.fullmatch(r'\d{10}', phone_number) is not None

def validate_passcode(passcode):
    # Check if the phone number is exactly 10 digits
    return re.fullmatch(r'\d{6}', passcode) is not None


def register_phone_number(phone_number):
    if phone_number in registered_phone_numbers:
        return False  # Phone number already exists
    registered_phone_numbers.add(phone_number)
    return True  # Successfully registered


def register_passcode():
    while True:
        passcode = input("Please Enter 6-digit passcode! Make sure you remember it: ")
        if not validate_passcode(passcode):
            print("Invalid passcode. Try again.")
            continue
        # encoding security code using KDF
        # Generate a random salt
        salt = os.urandom(16)
        print(f"Generated Salt (Base64): {base64.b64encode(salt).decode()}")
        # Derive a cryptographic key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,  # Length of the derived key in bytes
            salt=salt,
            iterations=1000  # Number of iterations for key strengthening
        )
        derived_key = kdf.derive(passcode.encode())
        return derived_key, salt

def SendBySecureChannel(phone_number):
    print(f"Sending SMS to {phone_number} for OTP...")
    user_code = input("Please enter the code you have received.")
    return user_code