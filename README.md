# Diffie-Hellman Key Exchange-Based Secure Chat System

## Project Overview

This project demonstrates the implementation of a secure chat system using the Diffie-Hellman Key Exchange protocol to establish a shared secret key over an insecure channel. The system ensures that only authorized users can read the messages, utilizing symmetric encryption for confidentiality.

## Key Features

### Diffie-Hellman Key Exchange
- Securely exchanges keys between two parties over a public network
- Ensures that even if the key exchange is intercepted, the shared secret remains private

### AES Encryption/Decryption
- Messages are encrypted with AES (Advanced Encryption Standard) using the derived shared key
- AES ensures that the messages are confidential and cannot be read without the correct key

### Socket-based Communication
- Implements a real-time chat system using TCP sockets, where users can send and receive encrypted messages

### Secure Session Key Generation
- Derives a symmetric session key from the shared secret to encrypt/decrypt messages securely
- Uses the PBKDF2 key derivation function to derive a 256-bit symmetric key from the Diffie-Hellman shared secret

## Technical Stack

- **Cryptography**: Python's `cryptography` library for Diffie-Hellman key exchange, AES encryption, and key derivation
- **Networking**: Python's `socket` module for real-time communication between a client and a server
- **Encryption**: AES (Advanced Encryption Standard) in CBC mode for message encryption

## How It Works

### Key Exchange
1. Both parties (client and server) generate private and public Diffie-Hellman keys
2. They exchange public keys and compute a shared secret
3. This secret is used to generate a symmetric encryption key using PBKDF2

### Message Encryption
1. Once the shared secret is established, messages are encrypted using AES-256 in CBC mode
2. The encrypted messages are sent over the network
3. The receiving party decrypts the message using the symmetric key derived from the shared secret

### Real-time Secure Chat
- Users can send and receive encrypted messages in real-time
- All communications remain private and secure

## Installation

1. Clone or download this repository
2. Create a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

**Note**: On macOS, you may need to use a virtual environment due to system Python protection. Always activate the virtual environment before running the server or client.

## Usage Instructions

### Step 1: Start the Server

In one terminal window, activate the virtual environment (if using one) and run:

```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
python3 server.py
```

The server will start listening on `localhost:12345` (default). You should see:

```
[*] Server listening on localhost:12345
[*] Waiting for client connection...
```

### Step 2: Connect with a Client

In another terminal window, activate the virtual environment (if using one) and run:

```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
python3 client.py
```

Or specify a custom host and port:

```bash
python3 client.py <host> <port>
```

Example:
```bash
python client.py localhost 12345
```

### Step 3: Start Chatting

Once the secure connection is established, you can:

- **Server side**: Type messages and press Enter to send encrypted messages to the client
- **Client side**: Type messages and press Enter to send encrypted messages to the server
- **Exit**: Type `exit` in either terminal to close the connection

### Example Session

**Server Terminal:**
```
[*] Server listening on localhost:12345
[*] Waiting for client connection...
[*] New connection from ('127.0.0.1', 54321)
[*] Secure connection established with ('127.0.0.1', 54321)
[*] You can now send encrypted messages. Type 'exit' to quit.

Hello, client!
[Client]: Hi, server! This is encrypted.
```

**Client Terminal:**
```
[*] Connecting to localhost:12345...
[*] Connected to server
[*] Secure connection established!
[*] You can now send encrypted messages. Type 'exit' to quit.

[Server]: Hello, client!
Hi, server! This is encrypted.
```

## Security Features

1. **Diffie-Hellman Key Exchange**: Uses 2048-bit parameters for secure key exchange
2. **PBKDF2 Key Derivation**: Derives a 256-bit symmetric key with 100,000 iterations
3. **AES-256-CBC Encryption**: Uses industry-standard AES encryption with CBC mode
4. **Random IVs**: Each message uses a unique initialization vector (IV) for enhanced security

## Project Structure

```
diffie/
├── server.py          # Server implementation
├── client.py          # Client implementation
├── requirements.txt   # Python dependencies
└── README.md         # This file
```

## Implementation Details

### Server (`server.py`)
- Listens for incoming connections on a specified host and port
- Handles the Diffie-Hellman key exchange with each client
- Manages encrypted message transmission and reception
- Supports multiple concurrent connections (one at a time per thread)

### Client (`client.py`)
- Connects to the server and performs key exchange
- Sends and receives encrypted messages
- Provides a simple command-line interface for chatting

## Why This Project?

- **Cryptographic Implementation**: Showcases ability to implement a cryptographic protocol and integrate it with networking to build secure systems
- **Practical Security**: Demonstrates understanding of both theoretical cryptographic concepts and practical implementation
- **Real-world Application**: A practical example of building a secure communication system, a critical skill in software development and cybersecurity

## Security Considerations

**Note**: This is an educational project. For production use, consider:

- Using TLS/SSL for additional transport layer security
- Implementing proper authentication mechanisms
- Using random salts for PBKDF2 (currently uses a fixed salt for simplicity)
- Adding message authentication codes (MACs) to prevent tampering
- Implementing proper error handling and connection management
- Using secure random number generators for all cryptographic operations