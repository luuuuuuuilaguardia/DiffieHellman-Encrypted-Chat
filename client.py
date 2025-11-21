#!/usr/bin/env python3

import socket
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class SecureChatClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.backend = default_backend()
        self.symmetric_key = None
        
    def derive_key(self, shared_secret):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'secure_chat_salt',
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(shared_secret)
    
    def encrypt_message(self, message, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_data, key):
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length]
        
        return message.decode('utf-8')
    
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"[*] Connecting to {self.host}:{self.port}...")
            self.socket.connect((self.host, self.port))
            print("[*] Connected to server")
            
            param_length_bytes = self.socket.recv(4)
            if len(param_length_bytes) != 4:
                raise Exception("Failed to receive parameter length")
            
            param_length = int.from_bytes(param_length_bytes, 'big')
            parameters_bytes = self.socket.recv(param_length)
            
            if len(parameters_bytes) != param_length:
                raise Exception("Failed to receive complete parameters")
            
            parameters = serialization.load_pem_parameters(
                parameters_bytes,
                backend=self.backend
            )
            
            key_length_bytes = self.socket.recv(4)
            if len(key_length_bytes) != 4:
                raise Exception("Failed to receive key length")
            
            server_key_length = int.from_bytes(key_length_bytes, 'big')
            server_public_key_bytes = self.socket.recv(server_key_length)
            
            if len(server_public_key_bytes) != server_key_length:
                raise Exception("Failed to receive complete public key")
            
            server_public_key = serialization.load_pem_public_key(
                server_public_key_bytes,
                backend=self.backend
            )
            
            client_private_key = parameters.generate_private_key()
            client_public_key = client_private_key.public_key()
            
            client_public_key_bytes = client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            key_length = len(client_public_key_bytes)
            self.socket.send(key_length.to_bytes(4, 'big'))
            self.socket.send(client_public_key_bytes)
            
            shared_secret = client_private_key.exchange(server_public_key)
            self.symmetric_key = self.derive_key(shared_secret)
            
            print("[*] Secure connection established!")
            print("[*] You can now send encrypted messages. Type 'exit' to quit.\n")
            
            return True
            
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return False
    
    def start_chat(self):
        if not self.symmetric_key:
            print("[!] No symmetric key established. Cannot start chat.")
            return
        
        def receive_messages():
            while True:
                try:
                    length_bytes = self.socket.recv(4)
                    if not length_bytes:
                        break
                    message_length = int.from_bytes(length_bytes, 'big')
                    
                    encrypted_message = b''
                    while len(encrypted_message) < message_length:
                        chunk = self.socket.recv(message_length - len(encrypted_message))
                        if not chunk:
                            break
                        encrypted_message += chunk
                    
                    if len(encrypted_message) != message_length:
                        break
                    
                    decrypted_message = self.decrypt_message(encrypted_message, self.symmetric_key)
                    print(f"[Server]: {decrypted_message}")
                    
                    if decrypted_message.lower() == 'exit':
                        break
                        
                except Exception as e:
                    print(f"[!] Error receiving message: {e}")
                    break
            
            print("[*] Connection closed")
            if self.socket:
                self.socket.close()
        
        receive_thread = threading.Thread(target=receive_messages, daemon=True)
        receive_thread.start()
        
        try:
            while True:
                message = input()
                if message.lower() == 'exit':
                    break
                
                encrypted = self.encrypt_message(message, self.symmetric_key)
                message_length = len(encrypted)
                self.socket.send(message_length.to_bytes(4, 'big'))
                self.socket.send(encrypted)
                
        except KeyboardInterrupt:
            print("\n[*] Closing connection...")
        except Exception as e:
            print(f"[!] Error sending message: {e}")
        finally:
            if self.socket:
                self.socket.close()


if __name__ == "__main__":
    import sys
    
    host = 'localhost'
    port = 12345
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    client = SecureChatClient(host, port)
    if client.connect():
        client.start_chat()
    else:
        print("[!] Failed to establish connection")
