## Overview

Welcome to **FriendLy**, **secure end-to-end communication system**
1. **Client**: Handles secure communication for individual users.
2. **Server**: Manages client connections, verifies authenticity, and facilitates secure communication between clients.

---

## Getting Started

### Prerequisites

- **Python 3.9+**
- Required libraries:
  ```bash
  pip install cryptography
  ```

---

### Files Description

#### 1. `Client.py`

This file contains the implementation of the client-side logic.

**Key Features:**

- **ECDH Key Exchange**: Generates a private-public key pair and derives a symmetric key for communication.
- **AES Encryption**: Encrypts and decrypts messages using a derived symmetric key.
- **Message Signing**: Uses ECDSA to sign messages, ensuring authenticity.
- **Server Interaction**:
  - Connects to the server.
  - Authenticates using a verification code.
  - Exchanges keys securely with the server and other clients.
- **Commands**:
  - `chat <phone>`: Initiates a secure chat with another client.
  - `send <phone> <message>`: Sends an encrypted message to another client.
  - `quit`: Disconnects the client from the server.

**Usage:**
Run the client script and follow the prompts:

```bash
python Client.py
```


#### 2. `Server.py`

This file contains the implementation of the server-side logic.

**Key Features:**

- **Client Registration**: Authenticates clients using a verification code.
- **ECDH Key Exchange**: Facilitates secure key exchange between clients.
- **Message Forwarding**: Relays encrypted messages between clients.
- **Offline Message Storage**: Stores messages for offline clients, delivering them when they reconnect.

**Usage:**
Run the server script to start listening for client connections:

```bash
python Server.py
```

---
### Client Commands

After running the client, use the following commands:

- **Initiate Chat**: Establishes a secure session with another client.
  ```
  chat <phone>
  ```
- **Send Message**: Encrypts and sends a message to another client.
  ```
  send <phone> <message>
  ```
- **Quit**: Disconnects from the server.
  ```
  quit
  ```
## System Workflow

### 1. Authentication

1. The client connects to the server.
2. The server sends a 6-digit verification code.
3. The client provides the code to authenticate.
4. Upon success, the server registers the client and establishes a session.

### 2. Key Exchange

1. The server facilitates ECDH key exchange between clients.
2. Clients derive a symmetric key for encryption using the shared secret and salt.

### 3. Communication

1. Messages are encrypted using AES and signed with ECDSA.
2. The server relays messages to the intended recipient.
3. Offline messages are stored and delivered when the recipient reconnects.

---

## Technical Details

### Cryptography

- **ECDH**: Used for secure key exchange.
- **AES (CBC mode)**: Used for encrypting messages.
- **ECDSA**: Used for signing and verifying messages.

### Threading

- Both client and server use threading for handling multiple operations concurrently:
  - The client can send and receive messages simultaneously.
  - The server manages multiple client connections.

---

## Error Handling

### Client Errors

- **Connection Issues**: Logs errors if the server is unreachable.
- **Invalid Commands**: Notifies users of invalid input.

### Server Errors

- **Invalid Keys**: Logs errors during key exchange or verification.
- **Offline Message Limits**: Notifies the sender if the recipient's offline message limit is reached.

---
