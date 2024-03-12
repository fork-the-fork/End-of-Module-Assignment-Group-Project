import socket
import sys
import time
from datetime import datetime
from pathlib import Path
import json
import pickle
import xml.etree.ElementTree as ET
import configparser
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from threading import Thread

class InvalidHeader(Exception):
    """The server sent an invalid header."""

class DuplicateSession(Exception):
    """A second session was opened on the same socket."""

class UnsupportedTransfer(Exception):
    """An unsupported file transfer was requested."""

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
    def __init__(self, config):
        self.initialise_server_settings(config)
        self.initialise_encryption_context()
    
    def initialise_server_settings(self, config):
        # Encryption Settings
        encryption_conf = config["encryption"]
        self.encryption_enabled = encryption_conf["enabled"]
        self.public_key_file = encryption_conf["public_key_file"]
        self.private_key_file = encryption_conf["private_key_file"]

        # Server Output Settings
        output_conf = config["output"]
        self.file_output_enabled = output_conf["file_output_enabled"]
        self.file_output_directory = output_conf["file_output_directory"]
        self.file_output_format = output_conf["file_output_format"]
        self.file_name_format = output_conf["file_name_format"]
        self.print_output_enabled = output_conf["print_output_enabled"]

        # Serialization Settings
        serializtion_conf = config["serialization"]
        self.enable_pickle = serializtion_conf["enable_pickle"]

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
    def __init__(self, src_ip, sock, handler, private_key=None, stream=False):
        self.data_type = None
        self.serialize_format = None
        self.encrypted = None
        self.transfer_size = None

        self.src_ip = src_ip
        self.sock = sock
        self.handler = handler
        self.private_key = private_key

        self.print = False
        self.output_file = None
        self.output_format = None
        self.payload = bytearray()

        # Read the next byte (meta_byte) from the socket only on init
        meta_byte = read_from_socket_upto_target(self.sock, 1)
        self.unpack_meta_byte(meta_byte)

        # Encryption validation
        if self.encrypted and not self.handler.enable_encryption:
            raise UnsupportedTransfer("Encryption Disabled")
        
        # Data type validation
        if not self.data_type:
            raise UnsupportedTransfer("Invalid Data Type specified")
        
        # Serialization validation
        if not self.serialize_format:
            raise UnsupportedTransfer("Invalid serialization format specified.")
        elif self.serialize_format == "binary" and not self.handler.pickle_enabled:
            raise UnsupportedTransfer("Pickling disabled.")

        # If the serialize format is not 0 (plaintext) then the file cannot be
        # returned until the whole session is complete
        if self.serialize_format == 0:
            self.streamable = stream
        else:
            self.streamable = False
        
        if self.handler.file_output_format == "original":
            self.output_format = self.serialize_format
        else:
            self.output_format = "json"
        
        # Open up streams ready for writing
        if self.handler.file_output_enabled:
            file_name = self.handler.file_name_format.format(
                timestamp=datetime.strftime(datetime.utcnow(), "%Y-%m-%dT%H-%M-%SZ"),
                source=src_ip,
                format = self.output_format
                )
            file_path = Path(self.handler.file_output_directory) / file_name
            self.output_file = open(file_path, "wb")
        if self.handler.print_output_enabled:
            self.print = True
    
    def _close(self):
        if self.output_file:
            self.output_file.close()
        
    
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
            self.serialize_format = "txt"
        elif serialize_format == 1:
            self.serialize_format = "binary"
        elif serialize_format == 2:
            self.serialize_format = "json"
        elif serialize_format == 3:
            self.serialize_format = "xml"
            
        self.encrypted = (meta_byte >> 1) & 1
    
    def _finalise_payload(self, payload):
        # Deserialize if file_output_format is not original or if printing to screen
        if self.handler.file_output_format != "original" or not self.handler.print_output_enabled:
            if self.data_type == "dictionary":
                if self.serialize_format == 'binary':
                    deserialized = pickle.loads(payload)
                elif self.serialize_format == 'json':
                    deserialized = json.loads(payload.decode("utf-8"))
                elif self.serialize_format == 'xml':
                    root = ET.fromstring(payload)
                    deserialized = {child.tag: child.text for child in root}
                if self.handler.file_output_format == "json":
                    deserialized = json.dumps(deserialized, indent=4)
            else:
                deserialized = payload.decode("utf-8")
        if self.output_file:
            if self.handler.file_output_format == "original":
                self.output_file.write(payload)
            else:
                self.output_file.write(deserialized.encode("utf-8"))
        if self.print:
            print(f"Recieved the following {self.serialize_format} message from {self.src_ip}:")
            print("---" * 20)
            print(deserialized)
            print("---" * 20)
    
    def recieve_upload(self, final):
        # Payload always prefixed with two-bytes indicating size
        size_bytes = read_from_socket_upto_target(self.sock, 2)
        self.transfer_size = int.from_bytes(size_bytes,"big")
        payload = read_from_socket_upto_target(self.sock, self.transfer_size)
        if self.encrypted:
            payload = self.decrypt(payload)
        if self.streamable:
            self._finalise_payload(payload)
        else:
            self.payload += payload
        if final:
            self._finalise_payload(self.payload)
            self._close()
         
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
                self.session = TransferSession(self.ip, self.sock, self.handler)
            # Ensure there is an active session before recieving:
            elif not self.session:
                raise InvalidHeader("Uninitialised session")
            # Recieve the upload if ready (enough to deserialise)
            self.session.recieve_upload(final=self.final)

            # Remove the session if this is the final packet.
            if self.final:
                self.session = None         

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

def main():
    config = configparser.ConfigParser()

    etc_dir = Path(__file__).parent.parent / "etc"
    default_config_filename = str(etc_dir / "default.ini")
    active_config_filename = str(etc_dir / "config.ini")
    config.read((default_config_filename, active_config_filename))
    print(config.sections())
    handler = ServerHandler(config)

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #tcpsock.settimeout(30)
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
    
if __name__ == "__main__":
    main()