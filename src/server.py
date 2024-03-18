import socket
import utils.paths as paths
from datetime import datetime
import json
import pickle
import xml.etree.ElementTree as ET
import configparser
from cryptography.fernet import Fernet
from threading import Thread

PRINTFORMAT = """
===========================================
Message Recieved
Format: {format}
Source: {src_ip}
Encrypted: {encrypted}
-------------------------------------------
{message}
-------------------------------------------
===========================================
"""

class SessionException(Exception):
    """Generic exception to capture issues related to file transfer."""

class InvalidHeader(SessionException):
    """The server sent an invalid header."""

class DuplicateSession(SessionException):
    """A second session was opened on the same socket."""

class UnsupportedTransfer(SessionException):
    """An unsupported file transfer was requested."""

class EncryptionError(SessionException):
    """An encryption error occured."""

TCP_IP = 'localhost'
TCP_PORT = 6868
BUFFER_SIZE = 1024

def extract_bits(int_byte, pos, count):
    # Right shift the number by p-1 bits to get the desired bits at the rightmost end of the number
    shifted_number = int_byte >> 8 - pos - count

    # Mask the rightmost k bits to get rid of any additional bits on the left
    mask = (1 << count) - 1
    return shifted_number & mask
    # END

def read_from_socket_upto_target(sock, target):
    data = bytearray()
    while target > 0:
        buffer = sock.recv(min(target, BUFFER_SIZE), socket.MSG_WAITALL)
        data += buffer
        target -= len(buffer)
    return data

class ServerContext():
    def __init__(self, config):
        self.initialise_server_settings(config)
        self.initialise_encryption_context()
    
    def initialise_server_settings(self, config):
        # Encryption Settings
        encryption_conf = config["encryption"]
        self.encryption_enabled = encryption_conf.getboolean("enabled")
        symmetric_key_file_name = encryption_conf["symmetric_key_file"]
        self.symmetric_key_file = paths.expand_path(symmetric_key_file_name)

        # Server Output Settings
        output_conf = config["output"]
        self.file_output_enabled = output_conf.getboolean("file_output_enabled")
        file_output_directory_name = output_conf["file_output_directory"]
        self.file_output_directory = paths.expand_path(file_output_directory_name)
        self.dictionary_output_format = output_conf["dictionary_output_format"]
        self.file_name_format = output_conf["file_name_format"]
        self.print_output_enabled = output_conf.getboolean("print_output_enabled")

        # Serialization Settings
        serializtion_conf = config["serialization"]
        self.pickle_enabled = serializtion_conf.getboolean("pickle_enabled")

    def initialise_encryption_context(self):
        self.symmetric_key = None
        if self.encryption_enabled:
            with open(self.symmetric_key_file, "rb") as key_file:
                raw_key = key_file.read()
            self.symmetric_key = Fernet(raw_key)

class TransferSession():
    def __init__(self, src_ip, sock, server_context, private_key=None, stream=False):
        self.data_type = None
        self.serialize_format = None
        self.encrypted = None
        self.transfer_size = None

        self.src_ip = src_ip
        self.sock = sock
        self.server_context = server_context
        self.private_key = private_key

        self.print = False
        self.output_file = None
        self.output_format = None
        self.payload = bytearray()

        # Read the next byte (meta_byte) from the socket only on init
        meta_byte = read_from_socket_upto_target(self.sock, 1)
        self.unpack_meta_byte(meta_byte)

        # Encryption validation
        if self.encrypted and not self.server_context.encryption_enabled:
            raise UnsupportedTransfer("Encryption Disabled")
        
        # Data type validation
        if not self.data_type:
            raise UnsupportedTransfer("Invalid Data Type specified")
        
        # Serialization validation
        if not self.serialize_format:
            raise UnsupportedTransfer("Invalid serialization format specified.")
        elif self.serialize_format == "binary" and not self.server_context.pickle_enabled:
            raise UnsupportedTransfer("Pickling disabled.")

        # If the serialize format is not 0 (plaintext) then the file cannot be
        # returned until the whole session is complete
        if self.serialize_format == 0:
            self.streamable = stream
        else:
            self.streamable = False
        
        # Output in original format unless file is a dictionary and output mode
        # is set to json.
        self.output_format = self.serialize_format
        if (self.data_type == "dictionary" and
            self.server_context.dictionary_output_format == "json"):
            self.output_format = "json"
        
        # Open up streams ready for writing
        if self.server_context.file_output_enabled:
            file_name = self.server_context.file_name_format.format(
                timestamp=datetime.strftime(datetime.utcnow(), "%Y-%m-%dT%H-%M-%S-%fZ"),
                source=src_ip,
                format = self.output_format
                )
            file_path = self.server_context.file_output_directory / file_name
            self.output_file = open(file_path, "wb")
        if self.server_context.print_output_enabled:
            self.print = True
    
    def close(self):
        if self.output_file:
            self.output_file.close()
    
    def decrypt(self,payload):
        try:
            return self.server_context.symmetric_key.decrypt(payload)
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
        # Deserialize if dictionary_output_format is not original or if printing to screen
        if (self.server_context.dictionary_output_format != "original" or
            self.server_context.print_output_enabled):
            if self.data_type == "dictionary":
                if self.serialize_format == 'binary':
                    deserialized = pickle.loads(payload)
                elif self.serialize_format == 'json':
                    deserialized = json.loads(payload.decode("utf-8"))
                elif self.serialize_format == 'xml':
                    root = ET.fromstring(payload)
                    deserialized = {child.tag: child.text for child in root}
                if self.server_context.dictionary_output_format == "json":
                    deserialized = json.dumps(deserialized, indent=4)
            else:
                deserialized = payload.decode("utf-8")
        if self.output_file:
            if self.server_context.dictionary_output_format == "original":
                self.output_file.write(payload)
            else:
                self.output_file.write(deserialized.encode("utf-8"))
        if self.print:
            print(PRINTFORMAT.format(format=self.serialize_format,
                                     src_ip=self.src_ip,
                                     encrypted=repr(bool(self.encrypted)),
                                     message=deserialized))
    
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
            self.close()

class ClientThread(Thread):

    def __init__(self,ip,port,sock,server_context):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock
        self.server_context = server_context
        #print " New thread started for "+ip+":"+str(port)
        self.session = None
        self.buffer = bytearray()
        # Operation Byte
        self.operation_mode = None
        self.init = None
        self.final = None
        print(f"Connection initiated by {ip}:{port}.")
    
    def unpack_operation_byte(self, op_byte):
        if not isinstance(op_byte, int):
            op_byte = int.from_bytes(op_byte, "big")
        status = extract_bits(op_byte, 0, 4)
        if status == 0:
            self.operation_mode = "TRANSFER"
        elif status == 1:
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
                self.session = TransferSession(self.ip, self.sock, self.server_context)
            # Ensure there is an active session before recieving:
            elif not self.session:
                raise InvalidHeader("Uninitialised session")
            # Recieve the upload if ready (enough to deserialise)
            self.session.recieve_upload(final=self.final)

            # Remove the session if this is the final packet.
            if self.final:
                self.session = None  

        elif self.operation_mode == "END":
            print(f"Connection closed by {self.ip}:{self.port}.")
            self.sock.shutdown(2)
            self.sock.close()
            if self.session:
                self.session.close()
            return 0

    def run(self):
        while True:
            try:
                if self.session_controller() is not None:
                    break
            except SessionException as e:
                print(f"Transfer issue occured from {self.ip}: {repr(e)}")
                break

def main():
    config = configparser.ConfigParser()

    etc_dir = paths.get_project_root() / "etc"
    default_config_filename = str(etc_dir / "default.ini")
    active_config_filename = str(etc_dir / "config.ini")
    config.read((default_config_filename, active_config_filename))
    server_context = ServerContext(config)

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #tcpsock.settimeout(30)
    tcpsock.bind((TCP_IP, TCP_PORT))
    print("Server started.")
    threads = []
    while True:
        tcpsock.listen(5)
        (conn, (ip,port)) = tcpsock.accept()
        newthread = ClientThread(ip,port,conn,server_context)
        newthread.start()
        threads.append(newthread)

    for t in threads:
        t.join()
    
if __name__ == "__main__":
    main()