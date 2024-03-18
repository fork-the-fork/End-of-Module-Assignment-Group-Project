"""
This file contains the client-side code.
"""

import socket
import json
import pickle
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet

messages = ["Hello", "GroupB!"]
MESSAGE_COUNT = len(messages)

class ClientSession():
    """
    This class creates the ClientSession object which..
    """
    def __init__(self, encryption_key_file=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if encryption_key_file:
            self.enable_encryption(encryption_key_file)
        else:
            self.encrypted = False

    def enable_encryption(self, key_file_name):
        """
        The enable_encryption function ...

        :param key_file_name:
        """
        self.encrypted = True
        with open(key_file_name, "rb") as key_file:
            raw_key = key_file.read()
        self.encryption_key = Fernet(raw_key)

    def open(self, host="127.0.0.1", port=6868):
        """
        The open function ...

        :param host: localhost
        :param port: port the client runs on on the server
        """
        self.sock.connect((host,port))

    def _transfer_raw(self, data_type, serialize_format, payload):
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

    def _serialize_dict(self, data, format):
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

    def send_dictionary(self, dic, encoding):
        payload = self._serialize_dict(dic, encoding)
        self._transfer_raw("dictionary", encoding, payload)

    def send_text(self, msg):
        if not isinstance(msg, (bytes, bytearray)):
            msg = msg.encode("utf-8")
        self._transfer_raw("text", "plaintext", msg)

    def close(self):
        close_session_bytes = (1 << 4).to_bytes(1,"big")
        self.sock.send(close_session_bytes)

if __name__ == "__main__":
    big_dic = {i: i+1 for i in range(0 , 10000)}
    client = ClientSession()
    client.open()
    client.send_dictionary(big_dic, "json")
    client.close()

    client = ClientSession()
    client.open()
    client.send_dictionary({"ABC": "DEF"}, "xml")
    client.send_text("Hello World!")
    client.close()
