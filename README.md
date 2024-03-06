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

#Both the client and the server use the TCP Protocol for communication
#The client is located at IP Address:192.168.x.xx and port: 8080
The server is located at IP address:192.168.x.xx and port: 6868
Both client and server communication are encrypted using fernet Encryption method and we use AES (advanced encryption standard) for encryption in storage
The client send two types of data to the server: a dictionary and an encrypted text file
The dictionary data is sent directly as part of communication
The file data is encrypted using fernet mothod before being sent to the server
Python socket are used to communication in both client and server
The client side utilizes pickle.dump () to Serializ the dictionary data into a binary format
BUFFER_SIZE, denoting the size of the buffer used for sending and receiving data

## Unit test

## license 
Distributed under the MIT License. See LICENSE.txt for more information.

## Requirements
No need specifict dictionary/binary to run the code as the code is written by basic Python dictionary only.
Recommend to open by visual studio
