## End_Module_Assignment_Group B
## Members: Aljunaydi, Azmi Chahal, Dang Dong, Thomas Lundie, Adhir Soechit

## Overview
This project implements a client-server network where the client can send dictionary data or text files to the server. 
The client can specify the pickling format for dictionary data and also choose to encrypt files before sending.

## Architecture

    +--------------------------+             +-----------------------+
    |        Client            |             |         Server        |
    | IP: 192.168.x.xx         |             | IP: 192.168.x.xx      |
    | Port: 8080               |             | Port: 6868            |
    | Protocol: TCP            |             | Protocol: TCP         |
    | Encryption: Fernet       |             | Encryption: AES+Fernet|
    | Data:                    |             | Data:                 |
    |   - Dictionary           |             |   - Encrypted File    |
    |   - Encrypted File       |             |   - Dictionary        |
    |   - Serialized Data      |             |                       |
    +--------------------------+             +-----------------------+
       Python Socket                                 Python Socket
             |                                              |
             +-----------------TCP/IP-----------------------+
                         BUFFER_SIZE: 1111               

##### Both the client and the server use the TCP Protocol for communication
##### The client is located at IP Address:192.168.x.xx and port: 8080
##### The server is located at IP address:192.168.x.xx and port: 6868
##### Both client and server communication are encrypted using fernet Encryption method and we use AES (advanced encryption standard) for encryption in storage
##### The client send two types of data to the server: a dictionary and an encrypted text file
##### The dictionary data is sent directly as part of communication
##### The file data is encrypted using fernet mothod before being sent to the server
##### Python socket are used to communication in both client and server
##### The client side utilizes pickle.dump () to Serializ the dictionary data into a binary format
##### BUFFER_SIZE, denoting the size of the buffer used for sending and receiving data

## Unit test

## license 
Distributed under the MIT License. See LICENSE.txt for more information.

## Instructions:
1. Setup:
   - Ensure you have Python installed on your machine.
   - Clone the project repository from the Git repo at: https://github.com/fork-the-fork/End-of-Module-Assignment-Group-Project/blob/main/LICENSE

2. Running the Server:
   - Open a terminal or command prompt.
   - Navigate to the directory containing server.py.
   - Run the command: python server.py
   - The server will start listening for incoming connections on the specified host and port as above architectre

3. Running the Client:
   - Open another terminal or command prompt.
   - Navigate to the directory containing client.py.
   - Run the command: python client.py
   - The client will connect to the server and send dictionary data and files
