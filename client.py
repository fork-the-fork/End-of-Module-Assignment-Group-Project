import socket
import json

host = '127.0.0.1'
port = 5555

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

json_data = client_socket.recv(4096).decode('utf-8')

with open('recieved_list.json', 'w') as json_file:
    json_file.write(json_data)

acknowledgment_message = "Data received successfully"
client_socket.send(acknowledgment_message.encode('utf-8'))

client_socket.close()