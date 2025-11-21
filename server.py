#!/usr/bin/env python3

import socket
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class SecureChatServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.backend = default_backend()
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=self.backend)
        
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
    
    def handle_client(self, client_socket, address):
        try:
            print(f"[*] New connection from {address}")
            
            server_private_key = self.parameters.generate_private_key()
            server_public_key = server_private_key.public_key()
            
            parameters_bytes = self.parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            param_length = len(parameters_bytes)
            client_socket.send(param_length.to_bytes(4, 'big'))
            client_socket.send(parameters_bytes)
            
            server_public_key_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            key_length = len(server_public_key_bytes)
            client_socket.send(key_length.to_bytes(4, 'big'))
            client_socket.send(server_public_key_bytes)
            
            key_length_bytes = client_socket.recv(4)
            if len(key_length_bytes) != 4:
                raise Exception("Failed to receive key length")
            
            client_key_length = int.from_bytes(key_length_bytes, 'big')
            client_public_key_bytes = client_socket.recv(client_key_length)
            
            if len(client_public_key_bytes) != client_key_length:
                raise Exception("Failed to receive complete public key")
            
            client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes,
                backend=self.backend
            )
            
            shared_secret = server_private_key.exchange(client_public_key)
            symmetric_key = self.derive_key(shared_secret)
            
            print(f"[*] Secure connection established with {address}")
            print("[*] You can now send encrypted messages. Type 'exit' to quit.\n")
            
            def receive_messages():
                while True:
                    try:
                        length_bytes = client_socket.recv(4)
                        if not length_bytes:
                            break
                        message_length = int.from_bytes(length_bytes, 'big')
                        
                        encrypted_message = b''
                        while len(encrypted_message) < message_length:
                            chunk = client_socket.recv(message_length - len(encrypted_message))
                            if not chunk:
                                break
                            encrypted_message += chunk
                        
                        if len(encrypted_message) != message_length:
                            break
                        
                        decrypted_message = self.decrypt_message(encrypted_message, symmetric_key)
                        print(f"[Client]: {decrypted_message}")
                        
                        if decrypted_message.lower() == 'exit':
                            break
                            
                    except Exception as e:
                        print(f"[!] Error receiving message: {e}")
                        break
                
                print(f"[*] Connection closed with {address}")
                client_socket.close()
            
            receive_thread = threading.Thread(target=receive_messages, daemon=True)
            receive_thread.start()
            
            while True:
                try:
                    message = input()
                    if message.lower() == 'exit':
                        break
                    
                    encrypted = self.encrypt_message(message, symmetric_key)
                    message_length = len(encrypted)
                    client_socket.send(message_length.to_bytes(4, 'big'))
                    client_socket.send(encrypted)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Error sending message: {e}")
                    break
            
            client_socket.close()
            print("[*] Server connection closed")
            
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
            client_socket.close()
    
    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"[*] Server listening on {self.host}:{self.port}")
            print("[*] Waiting for client connection...")
            
            while True:
                client_socket, address = self.socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            if self.socket:
                self.socket.close()


if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
