import socket
import pickle
import json
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet

def deserialize_dict(data, format):
    if format == 'binary':
        return pickle.loads(data)
    elif format == 'json':
        return json.loads(data.decode('utf-8'))
    elif format == 'xml':
        root = ET.fromstring(data)
        return {child.tag: child.text for child in root}

def receive_data(sock, size=1024):
    return sock.recv(size)

def receive_file(sock, filename):
    with open(filename, 'wb') as f:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            f.write(data)

def decrypt_data(data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(data)


SERVER_IP = '127.0.0.1'
SERVER_PORT = 10000


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((SERVER_IP, SERVER_PORT))
    s.listen()

    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"Connected to {addr[0]}:{addr[1]}")

       
        dict_data = receive_data(conn)
        deserialization_format = 'json'  
        my_dict = deserialize_dict(dict_data, deserialization_format)
        print("Received Dictionary:", my_dict)

      
        file_data = receive_data(conn)
        if file_data == b'ENCRYPTED':
            key = conn.recv(1024)
            file_data = decrypt_data(receive_data(conn), key)
        filename = 'received_file.txt'
        receive_file(conn, filename)
        print(f"Received File: {filename}")
