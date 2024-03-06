import socket
import json
import pickle

host = '127.0.0.1'
port = 5555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(5)

print(f"Server listening on {host}:{port}")

client_socket, client_address = server.accept()

print(f"Connection accepted from {client_address}")

with open('list_1.json', 'r') as json_file:
    json_data = json_file.read().encode('utf-8')

client_socket.send(json_data)

acknowledgment = client_socket.recv(1024).decode('utf-8')
print(f"Acknowledgment from client: {acknowledgment}")

client_socket.close()
server.close()
