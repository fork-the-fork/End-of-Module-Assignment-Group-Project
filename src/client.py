"""
This module contains the client side code.
"""

import socket
import json
import pickle
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet
import utils.paths as paths
from pathlib import Path
from typing import Union

class ClientSession():
    """
    This class implements the ClientSession object which tracks a particular client session.
    The client session object can be used to open/close a session and send multiple files of varying types.

    Instance Attributes:
        sock: The client socket to connect to the server.
        encrypted: Whether the file transfer payload is encrypted.
        encryption_key: The symmetric key to be used for encryption.
    """
    def __init__(self, encryption_key_file: str = None) -> None:
        """
        Initialises the ClientSession and encryption context.
        Does not connect to server, use open() to connect to a server.

        Args:
            encryption_key_file: If specified, enables encryption with the given encryption key.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if encryption_key_file:
            self.enable_encryption(encryption_key_file)
        else:
            self.encrypted = False

    def enable_encryption(self, key_file_name: Union[Path, str]) -> None:
        """
        Enables encryption for subsequent file transfers.
        
        Args:
            key_file_name: The path to the symmetric key file to be used for encryption
        """
        self.encrypted = True
        expanded_key_file_path = paths.expand_path(key_file_name)
        with open(expanded_key_file_path, "rb") as key_file:
            raw_key = key_file.read()
        self.encryption_key = Fernet(raw_key)

    def open(self, host: str = "127.0.0.1", port: int = 6868):
        """
        Open a session to given host and port.
        
        Args:
            host: Server hostname/ip address (127.0.0.1 by default)
            port: Server port (6868 by default)
        """
        self.sock.connect((host,port))

    def _transfer_raw(self, data_type: str, serialize_format: str, payload: bytes) -> None:
        """
        Transfer raw is an _internal method not indended to be called outside of the instance.
        Use the send_text or send_dictionary methods instead.
        It does the main legwork of the transfer by iterating through a given payload:
            Serializes it with the given format.
            Chunks it into the correct payload sizes.
            Encrypts it.
            Appends appropriate headers and sends to the server.
        Args:
            data_type: The type of data being transmitted (text or dict).
            serialize_format: The format to serialize the payload with (txt, binary, xml, json).
            payload: The payload to be transmitted.
        """
        # First payload must contain the meta_byte
        if data_type == "text":
            data_type_int = 0
        elif data_type == "dictionary":
            data_type_int = 1

        if serialize_format == "plaintext":
            serialize_format_int = 0
        elif serialize_format == "binary":
            serialize_format_int = 1
        elif serialize_format == "json":
            serialize_format_int = 2
        elif serialize_format == "xml":
            serialize_format_int = 3

        meta_int = data_type_int << 5 | serialize_format_int << 2 | int(self.encrypted) << 1
        meta_byte = meta_int.to_bytes(1, "big")

        payload_steps = range(0,len(payload),65535)
        final_step = len(payload_steps) - 1
        init = 1
        final = 0
        for i, chunk_slice in enumerate(payload_steps):
            if i == final_step:
                final = 1
            packet_bytes = (0 << 4 | init << 3 | final << 2).to_bytes(1, "big")

            if i == 0:
                packet_bytes += meta_byte
                init = 0
            chunk = payload[chunk_slice:chunk_slice + 65535]
            if self.encrypted:
                chunk = self.encryption_key.encrypt(chunk)

            packet_bytes += len(chunk).to_bytes(2, "big")
            packet_bytes += chunk
            self.sock.send(packet_bytes)

    def _serialize_dict(self, data: dict, format: str) -> bytes:
        """
        serializes a dictionary using the specified format.
        Not intended to be called externally.

        Args:
            data: Dictionary to be encrypted
            format: Format to serialize dictionary with.
        
        Returns:
            Bytes object containing serialized dictionary.
        """
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

    def send_dictionary(self, dic: dict, serialize_format: str) -> None:
        """
        Wrapper for _transfer_raw to send a dictionary.
        Sends a dictionary to the previously open() server.
        Args:
            dic: The specified dictionary.
            serialize_format: The format to serialize the dictionary with.
        """
        if serialize_format not in ("binary", "json", "xml"):
            raise NotImplemented("Unsupported serialization format.")
        payload = self._serialize_dict(dic, serialize_format)
        self._transfer_raw("dictionary", serialize_format, payload)

    def send_text(self, msg: str) -> None:
        """
        Wrapper for _transfer_raw to send a text message.
        Sends a text message to the previously open() server.
        Args:
            msg: The specified text message.
        """
        if not isinstance(msg, (bytes, bytearray)):
            msg = msg.encode("utf-8")
        self._transfer_raw("text", "plaintext", msg)
    
    def send_text_file(self, file_name: str) -> None:
        """
        Wrapper for send_text to send a text message from a file.
        Sends a text file to the previously open() server.
        Args:
            file_name: The specified file_name.
        """
        expanded_file_name = paths.expand_path(file_name)
        with open(expanded_file_name,"rb") as f:
            text_contents = f.read()
        self.send_text(text_contents)

    def close(self) -> None:
        """
        Closes the opened client/server session.
        Sends an "END" message to the server and shutsdown the socket.
        """
        close_session_bytes = (1 << 4).to_bytes(1,"big")
        self.sock.send(close_session_bytes)
        self.sock.shutdown(2)

def main():
    """
    Demo the client functionality.
    """
    client = ClientSession()
    client.open()

    # Send a large dictionary with XML.
    big_dictionary = {"A" + str(i): str(i+1) for i in range(0 , 10000)}
    client.send_dictionary(big_dictionary, "xml")
    
    # Send a nested dictionary with JSON.
    client.send_dictionary({"a": {"b": {"d": {"e": {"f": "g"}}}}}, "json")

    # Send an unencrypted text.
    client.send_text("Hello World!")

    # Enable encryption for future transfers.
    client.enable_encryption("./etc/secret/example.key")

    # Send an encrypted pickled dictionary.
    client.send_dictionary({"Pickled": True, "Encrypted": True}, "binary")

    # Send an encrypted text.
    client.send_text("Encrypted")

    # Send a text file from disk.
    client.send_text_file("./.gitignore")

    # Close session
    client.close()

if __name__ == "__main__":
    main()
