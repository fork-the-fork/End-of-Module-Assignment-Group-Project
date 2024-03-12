import socket
import sys
import json
import pickle
import xml.etree.ElementTree as ET
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from threading import Thread

class InvalidHeader(Exception):
    """The server sent an invalid header."""

class DuplicateSession(Exception):
    """A second session was opened on the same socket."""

class EncryptionError(Exception):
    """An encryption error occured."""

TCP_IP = 'localhost'
TCP_PORT = 6868
BUFFER_SIZE = 1024

def read_from_socket_upto_target(sock, target):
    data = bytearray()
    while target > 0:
        buffer = sock.recv(min(target, BUFFER_SIZE), socket.MSG_WAITALL)
        data += buffer
        target -= len(buffer)
    return buffer

class ServerHandler():
    def __init__(self):
        self.initialise_server_settings()
        if server_mode == "PRINT":
            self.stream = sys.stdout
        else:
            self.stream = open(r"C:\Temp\hello.txt", "w")
        self.initialise_encryption_context()
    
    def initialise_server_settings(self):
        self.public_key_file = r"C:\Temp\pubkey.pem"
        self.private_key_file = r"C:\Temp\privatekey.pem"

    def initialise_encryption_context(self):
        with open(self.private_key_file, 'rb') as pem_in:
            pemlines = pem_in.read()
        self.private_key = load_pem_private_key(pemlines, None)
        
        with open(self.public_key_file, 'rb') as pem_in:
            pemlines = pem_in.read()
        self.public_key = load_pem_public_key(pemlines)      

    def write(self, string):
        print("Recieved the following message from client: ")
        self.stream.write(string)
    
    def flush(self):
        self.stream.write("\n")
        self.stream.flush()

class TransferSession():
    def __init__(self, sock, private_key=None, stream=False):
        self.data_type = None
        self.serialize_format = None
        self.encrypted = None
        self.transfer_size = None

        self.sock = sock
        self.private_key = private_key

        self.payload = bytearray()

        # Read the next byte (meta_byte) from the socket only on init
        meta_byte = read_from_socket_upto_target(self.sock, 1)
        self.unpack_meta_byte(meta_byte)

        # If the serialize format is not 0 (plaintext) then the file cannot be
        # returned until the whole session is complete
        if self.serialize_format == 0:
            self.streamable = stream
        else:
            self.streamable = False
    
    def decrypt(self,payload):
        try:
            message_decrypted = self.private_key.decrypt(
                payload,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return f"Decrypted Message: {message_decrypted}"
        except ValueError:
            raise EncryptionError

    def unpack_meta_byte(self, meta_byte):
        if not isinstance(meta_byte, int):
            meta_byte = int.from_bytes(meta_byte, "big")
        data_type = extract_bits(meta_byte, 0, 3)
        if data_type == 0:
            self.data_type = "text"
        elif data_type == 1:
            self.data_type = "dictionary"

        serialize_format = extract_bits(meta_byte, 3, 3)
        if serialize_format == 0:
            self.serialize_format = "plaintext"
        elif serialize_format == 1:
            self.serialize_format = "binary"
        elif serialize_format == 2:
            self.serialize_format = "json"
        elif serialize_format == 3:
            self.serialize_format = "xml"
            
        self.encrypted = (meta_byte >> 1) & 1
    
    def _finalise_payload(self, payload):
        if self.data_type == "dictionary":
            deserialized = None
            if self.serialize_format == 'binary':
                deserialized = pickle.loads(payload)
            elif self.serialize_format == 'json':
                deserialized = json.loads(payload.decode('utf-8'))
            elif self.serialize_format == 'xml':
                root = ET.fromstring(payload)
                deserialized = {child.tag: child.text for child in root}
            return json.dumps(deserialized, indent=4)
        else:
            return payload.decode("utf-8")
    
    def recieve_upload(self, final):
        # Payload always prefixed with two-bytes indicating size
        size_bytes = read_from_socket_upto_target(self.sock, 2)
        self.transfer_size = int.from_bytes(size_bytes,"big")
        payload = read_from_socket_upto_target(self.sock, self.transfer_size)
        if self.encrypted:
            payload = self.decrypt(payload)
        if self.streamable:
            return self._finalise_payload(payload)
        else:
            self.payload += payload
        if final:
            return self._finalise_payload(self.payload)
         
def extract_bits(int_byte, pos, count):
    # Right shift the number by p-1 bits to get the desired bits at the rightmost end of the number
    shifted_number = int_byte >> 8 - pos - count

    # Mask the rightmost k bits to get rid of any additional bits on the left
    mask = (1 << count) - 1
    return shifted_number & mask
    # END

class ClientThread(Thread):

    def __init__(self,ip,port,sock,handler):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock
        self.handler = handler
        #print " New thread started for "+ip+":"+str(port)
        self.session = None
        self.buffer = bytearray()
        # Operation Byte
        self.operation_mode = None
        self.init = None
        self.final = None
    
    def unpack_operation_byte(self, op_byte):
        if not isinstance(op_byte, int):
            op_byte = int.from_bytes(op_byte, "big")
        status = extract_bits(op_byte, 0, 4)
        if status == 0:
            self.operation_mode = "TRANSFER"
        elif status == 1:
            self.operation_mode = "REQUEST_PUBKEY"
        elif status == 2:
            self.operation_mode = "END"
        else:
            self.operation_mode = "ERROR"
        self.init = bool((op_byte >> 3) & 1)
        self.final = bool((op_byte >> 2) & 1)

    def session_controller(self):
        op_byte = read_from_socket_upto_target(self.sock, 1)
        self.unpack_operation_byte(op_byte)
        if self.operation_mode == "TRANSFER":
            # Initialise the transfer session if new.
            if self.init:
                if self.session:
                    raise DuplicateSession()
                self.session = TransferSession(self.sock)
            # Ensure there is an active session before recieving:
            elif not self.session:
                raise InvalidHeader("Uninitialised session")
            # Recieve the upload if ready (enough to deserialise)
            payload = self.session.recieve_upload(final=self.final)
            if payload:
                handler.write(payload)

            # Remove the session if this is the final packet.
            if self.final:
                self.session = None                
                handler.flush()
        elif self.operation_mode == "REQUEST_PUBKEY":
            response = bytearray()
            response += len(self.handler.public_key).to_bytes(2, "big")
            response += self.handler.public_key
            self.sock.send(response)

    def run(self):
        while True:
            try:
                self.session_controller()
            except InvalidHeader:
                pass

server_mode = "PRINT"
server_write = "CONTINUOUS"
# sever_mode = "SAVE"

handler = ServerHandler()

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((TCP_IP, TCP_PORT))
threads = []

while True:
    tcpsock.listen(5)
    #print "Waiting for incoming connections..."
    (conn, (ip,port)) = tcpsock.accept()
    #print 'Got connection from ', (ip,port)
    newthread = ClientThread(ip,port,conn,handler)
    newthread.start()
    threads.append(newthread)

for t in threads:
    t.join()