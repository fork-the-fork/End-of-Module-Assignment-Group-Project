"""
This file contains the server-side code.
"""

import socket
from utils import paths
from datetime import datetime
import json
import pickle
import xml.etree.ElementTree as ET
import configparser
from threading import Thread
from cryptography.fernet import Fernet
from typing import Union

BUFFER_SIZE = 1024
CLIENT_TIMEOUT = 30

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

def extract_bits(int_byte: int, pos: int, count: int) -> int:
    """
    Bit shifts the supplied int_byte to read {count} bits from position {pos}:
    e.g. Reading 4-bits from pos 1 of (01110100) would be 14 (00001110).
    Args:
        int_byte: the byte to read in integer format.
        pos: the bit-position to start reading (zero-based)
        count: the number of bits to count (at-least 1)

    Returns:
        The integer value of the shifted int_byte.
    """

    # Right shift the number to get desired bits at the rightmost end of the number
    shifted_number = int_byte >> 8 - pos - count

    # Mask the desired rightmost bits to get rid of any additional bits on the left
    mask = (1 << count) - 1
    return shifted_number & mask

def read_from_socket_upto_target(sock: socket.socket, target_size: int) -> bytearray:
    """
    Reads the exact number of target bytes from the specified socket.
    Using the BUFFER_SIZE. This function is blocking.
    Args:
        sock: the socket to read data from.
        target_size: the number of bytes to read from the socket.

    Returns:
        A bytearray of data from the socket.
    """

    data = bytearray()
    while target_size > 0:
        buffer = sock.recv(min(target_size, BUFFER_SIZE))
        data += buffer
        target_size -= len(buffer)
    return data

def initialize_server_context(config: configparser.ConfigParser) -> dict:
    """
    Initializes the server settings to meet the directive of the specified config file.
    This includes the configuration and encryption settings.
    Args:
        config: The merged final ini config.

    Returns:
        A dictionary containing the sever context (configuration and common files loaded).
    """
    server_context = {}

    # Listening settings
    listening_conf = config["listening"]
    server_context["tcp_host"] = listening_conf["host"]
    server_context["tcp_port"] = listening_conf.getint("port")

    # Encryption Settings
    encryption_conf = config["encryption"]
    server_context["encryption_enabled"] = encryption_conf.getboolean("enabled")
    symmetric_key_file_name = encryption_conf["symmetric_key_file"]
    server_context["symmetric_key_file"] = paths.expand_path(symmetric_key_file_name)

    # Server Output Settings
    output_conf = config["output"]
    server_context["stream_output"] = output_conf.getboolean("stream_output")
    server_context["file_output_enabled"] = output_conf.getboolean("file_output_enabled")
    file_output_directory_name = output_conf["file_output_directory"]
    server_context["file_output_directory"] = paths.expand_path(file_output_directory_name)
    server_context["dictionary_output_format"] = output_conf["dictionary_output_format"]
    server_context["file_name_format"] = output_conf["file_name_format"]
    server_context["print_output_enabled"] = output_conf.getboolean("print_output_enabled")

    # Serialization Settings
    serializtion_conf = config["serialization"]
    server_context["pickle_enabled"] = serializtion_conf.getboolean("pickle_enabled")

    # If required, load the encryption key
    symmetric_key = None
    if server_context["encryption_enabled"]:
        with open(server_context["symmetric_key_file"], "rb") as key_file:
            raw_key = key_file.read()
        symmetric_key = Fernet(raw_key)
    server_context["symmetric_key"] = symmetric_key

    return server_context

class TransferSession():
    """
    The TransferSession object represents a single instance of a file transfer.
    There is one TransferSession per file.
    It tracks the state of the transfer and the metadata of the file being transfered.
    A single packet/payload supports upto a maximum number of bytes, therefore,
    serialized payloads such as pickled dictionaries need to be stored in the payload attribute.
    and deserialized at the end. Unlike text files which can be outputted in chunks (streamable).

    Class Attributes:
        DATA_TYPE_INT_LOOKUP: Lookup for the data_type integer value
        DATA_TYPE_NAME_LOOKUP: Lookup for the data_type name value
        SERIALIZE_FMT_INT_LOOKUP: Lookup for the serialization format integer value
        SERIALIZE_FMT_NAME_LOOKUP: Lookup for the serialization format integer value

    Instance Attributes:
        meta_data: Stores the meta_data of the file being transferred.
        sock: The socket where the file is being transferred from.
        server_context: A dictionary containing the common server configuration.
        streamable: Whether or not the file can be streamed (written in chunks per packet)
        output_file: An open file io stream to write the transferred file to.
        payload: A bytearray to store the payload (for payloads spanning multiple packets).
    """
    DATA_TYPE_INT_LOOKUP = {0: "text",
                            1: "dictionary"}

    DATA_TYPE_NAME_LOOKUP = {v:k for k,v in DATA_TYPE_INT_LOOKUP.items()}

    SERIALIZE_FMT_INT_LOOKUP = {0: "txt",
                               1: "binary",
                               2: "json",
                               3: "xml"}

    SERIALIZE_FMT_NAME_LOOKUP = {v:k for k,v in SERIALIZE_FMT_INT_LOOKUP.items()}

    def __init__(self, sock: socket.socket, src_ip: str, server_context: dict) -> None:
        """
        Initializes the TransferSession.
        The first byte on the socket is the meta_byte containing the details of the transfer.
        This meta_byte is ingested and parsed and the transfer session is initalised by
        combining context from the meta_byte and the server_context.

        Args:
            sock: The socket to transfer from.
            src_ip: The source ip that initiated the session.
            server_context: A dictionary containing the common server configuration.
        """
        self.meta_data = {"data_type": None,
                          "serialize_format": None,
                          "encrypted": None,
                          "transfer_size": None,
                          "src_ip": src_ip,
                          "output_format": None}

        self.sock = sock
        self.server_context = server_context

        self.streamable = False
        self.output_file = None
        self.payload = bytearray()

        # Read the next byte (meta_byte) from the socket only on init
        meta_byte = read_from_socket_upto_target(self.sock, 1)
        self.unpack_meta_byte(meta_byte)

        # Encryption validation
        if self.meta_data["encrypted"] and not self.server_context["encryption_enabled"]:
            raise UnsupportedTransfer("Encryption Disabled")

        # Data type validation
        if not self.meta_data["data_type"]:
            raise UnsupportedTransfer("Invalid Data Type specified")

        # Serialization validation
        if not self.meta_data["serialize_format"]:
            raise UnsupportedTransfer("Invalid serialization format specified.")
        if (self.meta_data["serialize_format"] == "binary"
            and not self.server_context["pickle_enabled"]):
            raise UnsupportedTransfer("Pickling disabled.")

        # If the serialize format is not 0 (plaintext) then the file is not streamable
        # (e.g. it cannot be returned until the whole session is complete)
        if self.meta_data["serialize_format"] == "txt":
            self.streamable = self.server_context["stream_output"]

        # Output in original format unless file is a dictionary and output mode
        # is set to json.
        self.meta_data["output_format"] = self.meta_data["serialize_format"]
        if (self.meta_data["data_type"] == "dictionary" and
            self.server_context["dictionary_output_format"] == "json"):
            self.meta_data["output_format"] = "json"

        # Open up streams ready for writing
        if self.server_context["file_output_enabled"]:
            file_name = self.server_context["file_name_format"].format(
                timestamp=datetime.strftime(datetime.utcnow(), "%Y-%m-%dT%H-%M-%S-%fZ"),
                source=self.meta_data["src_ip"],
                format = self.meta_data["output_format"]
                )
            file_path = self.server_context["file_output_directory"] / file_name
            self.output_file = open(file_path, "wb")

    def close(self):
        """
        Closes any open file output IOs.
        """
        if self.output_file:
            self.output_file.close()
            self.output_file = None

    def decrypt(self, payload: bytes) -> bytes:
        """
        Decrypts the encrypted payload using context provided by the server_context settings.

        Args:
            payload: The encrypted payload.

        Returns:
            The decrypted payload.
        """
        try:
            return self.server_context["symmetric_key"].decrypt(bytes(payload))
        except ValueError as exc:
            raise EncryptionError from exc

    def unpack_meta_byte(self, meta_byte: Union[bytes, int]) -> None:
        """
        Unpacks the meta_byte into the self.meta_data attribute using the class lookups.
        The meta_byte contains the context about the transferred file including:
            data_type: What type of data is in the payload (text or dictionary).
            serialize_type: How the data is serialized.
            encrypted: Whether the payload is encrypted.

        Args:
            meta_byte: The meta_byte specified as a byte or integer.
        """
        if not isinstance(meta_byte, int):
            meta_byte = int.from_bytes(meta_byte, "big")

        # Extract data_type from bits 0 - 2
        data_type_int = extract_bits(meta_byte, 0, 3)
        self.meta_data["data_type"] = self.DATA_TYPE_INT_LOOKUP.get(data_type_int)

        # Extract serialize_format from bits 3 - 5
        serialize_format_int = extract_bits(meta_byte, 3, 3)
        self.meta_data["serialize_format"] = self.SERIALIZE_FMT_INT_LOOKUP.get(serialize_format_int)

        # Extract encryption value from bit 6
        self.meta_data["encrypted"] = (meta_byte >> 1) & 1

    def _finalise_payload(self, payload: bytes) -> None:
        """
        Finalises and outputs the transfered file payload.
        Deserializes, converts to specified output_format, and writes to file/stdout
        Depending depending on specified configuration in self.server_context

        Args:
            payload: The file payload ready to be outputted.
        """
        # Deserialize if dictionary_output_format is not original or if printing to screen
        if (self.server_context["dictionary_output_format"] != "original" or
            self.server_context["print_output_enabled"]):
            if self.meta_data["data_type"] == "dictionary":
                if self.meta_data["serialize_format"] == 'binary':
                    deserialized = pickle.loads(payload)
                elif self.meta_data["serialize_format"] == 'json':
                    deserialized = json.loads(payload.decode("utf-8"))
                elif self.meta_data["serialize_format"] == 'xml':
                    root = ET.fromstring(payload)
                    deserialized = {child.tag: child.text for child in root}
                if self.server_context["dictionary_output_format"] == "json":
                    deserialized = json.dumps(deserialized, indent=4)
            else:
                deserialized = payload.decode("utf-8")
        if self.output_file:
            if self.server_context["dictionary_output_format"] == "original":
                self.output_file.write(payload)
            else:
                self.output_file.write(deserialized.encode("utf-8"))
        if self.server_context["print_output_enabled"]:
            print(PRINTFORMAT.format(format=self.meta_data["serialize_format"],
                                     src_ip=self.meta_data["src_ip"],
                                     encrypted=repr(bool(self.meta_data["encrypted"])),
                                     message=deserialized))

    def recieve_upload(self, final: bool) -> None:
        """
        Recieved upload is the main entry point into TransferSession.
        It is intended to iterate through the socket and continue reading the inbound file.
        All payloads are pre-fixed with a big-endian 2-byte integer represent the packet size.
        Final is used to tell the transfersession that this is the final payload for this file.

        Args:
            final: Boolean specifying whether this is will be the final payload for this file.
        """
        # Payload always prefixed with two-bytes indicating size
        size_bytes = read_from_socket_upto_target(self.sock, 2)
        self.meta_data["transfer_size"] = int.from_bytes(size_bytes,"big")
        payload = read_from_socket_upto_target(self.sock, self.meta_data["transfer_size"])
        if self.meta_data["encrypted"]:
            payload = self.decrypt(payload)
        if self.streamable:
            self._finalise_payload(payload)
            if final:
                self.close()
        else:
            self.payload += payload
            if final:
                self._finalise_payload(self.payload)
                self.close()

class ClientThread(Thread):
    """
    The ClientThread object is a child of the Thread class from the Python threading library.
    Each client connection has a dedicated thread to enable multiple clients to connect at once.
    Each thread loops, iterating through the first byte of each packet the "operation byte".
    The operation byte contains an instruction from the client which informs the server
    about the upcoming payload.

    Class Attributes:
        OPERATION_MODE_LOOKUP: Lookup for the operation mode.
    
    Instance Attributes:
        ip: The source IP that opened the connection thread.
        port: The source port that opened the connection thread.
        sock: The socket where the session is being conducted from.
        server_context: A dictionary containing the common server configuration.
        session: The current file transfer session.
        init: Whether this payload is the first of the current session/operation.
        final: Whether this payload is the last of the current session/operation.
    """
    OPERATION_MODE_LOOKUP = {0: "TRANSFER",
                             1: "END"}

    def __init__(self, ip: str, port: int, sock: socket.socket, server_context: dict) -> None:
        """
        Initializes the ClientThread to track the current client/server session.
        """
        Thread.__init__(self)
        self.ip = ip
        self.sock = sock
        self.server_context = server_context
        self.session = None
        # Operation Byte
        self.operation_mode = None
        self.init = None
        self.final = None
        print(f"Connection initiated by {ip}:{port}.")

    def send_message(self, message: Union[str, bytes]) -> None:
        """
        Best effort to send a message to the client, however, fails silently.
        This is intentional to prevent interrupts to ongoing file transfers.

        Args:
            message: The operation_byte as integer or bytes object.

        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        try:
            self.sock.send(message)
        except socket.error:
            pass

    def unpack_operation_byte(self, op_byte: Union[int, bytes]) -> None:
        """
        Parses the operation byte into the client instructions.
        The operation_byte contains the context about the client's intentions including:
            operation_mode: What does the client intend to do (transfer or end).
            init: Is this the first payload of this operation.
            final: Is this the final payload of this operation.

        Args:
            op_byte: The operation_byte as integer or bytes object.

        """
        if not isinstance(op_byte, int):
            op_byte = int.from_bytes(op_byte, "big")

        operation_mode_int = extract_bits(op_byte, 0, 4)
        self.operation_mode = self.OPERATION_MODE_LOOKUP.get(operation_mode_int, "ERROR")

        self.init = bool((op_byte >> 3) & 1)

        self.final = bool((op_byte >> 2) & 1)

    def session_controller(self) -> int:
        """
        This is the main entry/iteration point for the ClientThread.
        The first byte on the socket is the operation_byte containing the instructions
        from the client. This operation_byte is ingested and parsed, which triggers
        the required instruction to initialise / iterate.

        Returns:
            Status. Non-zero represents an issue with the session, causing session to terminate.
        """
        op_byte = read_from_socket_upto_target(self.sock, 1)
        self.unpack_operation_byte(op_byte)
        if self.operation_mode == "TRANSFER":
            # Initialise the transfer session if new.
            if self.init:
                if self.session:
                    raise DuplicateSession()
                self.session = TransferSession(self.sock, self.ip, self.server_context)
            # Ensure there is an active session before recieving:
            elif not self.session:
                raise InvalidHeader("Uninitialised session")
            # Recieve the upload if ready (enough to deserialise)
            self.session.recieve_upload(final=self.final)

            # Remove the session if this is the final packet.
            if self.final:
                self.send_message("OK")
                self.session = None

        elif self.operation_mode == "END":
            print(f"Connection closed by {self.ip}.")
            self.sock.shutdown(2)
            self.sock.close()
            if self.session:
                self.session.close()
            return 1

        return 0

    def run(self) -> None:
        """
        The run function is called when the Thread is initialised and ready to be executed. 
        This iterates through the packets packets from the given client
        via the session_controller method.
        """
        while True:
            try:
                if self.session_controller() > 0:
                    break
            except Exception as exc: # pylint: disable=broad-exception-caught
                print(f"Issue occured with {self.ip}: {repr(exc)}")
                if isinstance(exc, socket.error):
                    # Socket has died, close thread.
                    break
                # If the issue was caused by the client, reply with the error details.
                if isinstance(exc, SessionException):
                    self.send_message(f"ERROR: {repr(exc)}")

def main() -> None:
    """
    The main function is called if the server module is executed directly.
    It initialises the server using the configuration specified in the ./etc/ directory
    And setups the threading context to handle multiple clients simultaeneously.
    """
    config = configparser.ConfigParser()

    etc_dir = paths.get_project_root() / "etc"
    default_config_filename = str(etc_dir / "default.ini")
    active_config_filename = str(etc_dir / "config.ini")
    config.read((default_config_filename, active_config_filename))
    server_context = initialize_server_context(config)
    print(server_context)

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpsock.bind((server_context["tcp_host"], server_context["tcp_port"]))
    tcpsock.listen(5)
    print("Server started.")
    threads = []
    while True:
        (conn, (ip,port)) = tcpsock.accept()
        conn.settimeout(CLIENT_TIMEOUT)
        newthread = ClientThread(ip, port, conn, server_context)
        newthread.start()
        threads.append(newthread)

    for t in threads:
        t.join()

# Call main() if executing as a module
if __name__ == "__main__":
    main()
