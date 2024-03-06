import socket
import pickle
import json
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet

def serialize_dict(data, format):
    if format == 'binary':
        return pickle.dumps(data)
    elif format == 'json':
        return json.dumps(data).encode('utf-8')
    elif format == 'xml':
        root = ET.Element('root')
        for key, value in data.items():
            child = ET.Element(key)
            child.text = str(value)
            root.append(child)
        return ET.tostring(root)

def send_data(sock, data):
    sock.sendall(data)

def send_file(sock, filename, encrypt=False):
    with open(filename, 'rb') as f:
        content = f.read()
        if encrypt:
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)
            content = cipher_suite.encrypt(content)
            sock.sendall(b'ENCRYPTED')
            sock.sendall(key)
        else:
            sock.sendall(b'UNENCRYPTED')
        sock.sendall(content)


SERVER_IP = '127.0.0.1'
SERVER_PORT = 10000


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, SERVER_PORT))
    my_dict = {'Course': 'Data Science',
               'Year': '2024', 
               'Level': 'Prof.'}

    serialization_format = 'json'
    serialized_dict = serialize_dict(my_dict, serialization_format)
    send_data(s, serialized_dict)
    filename = 'test.txt'
    encrypt_file = False
    send_file(s, filename, encrypt=encrypt_file)
