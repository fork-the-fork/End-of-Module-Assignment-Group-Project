import socket
import json
import pickle
import xml.etree.ElementTree as ET

messages = ["Hello", "GroupB!"]
message_count = len(messages)

class ClientSession():
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "127.0.0.1"
        port = 6868
        self.sock.connect((host,port))
    
    def _send_raw(self, data_type, serialize_format, payload):
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

        meta_int = data_type_int << 5 | serialize_format_int << 2
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

            packet_bytes += len(chunk).to_bytes(2, "big")
            packet_bytes += chunk
            self.sock.send(packet_bytes)

    def serialize_dict(self, data, format):
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
        payload = self.serialize_dict(dic, encoding)
        self._send_raw("dictionary", encoding, payload)
    
    def send_text(self, msg):
        if not isinstance(msg, (bytes, bytearray)):
            msg = msg.encode("utf-8")
        self._send_raw("text", "plaintext", msg)

client = ClientSession()
#client.send_text("Hello")
#client.send_text("World")
client.send_dictionary({"Hello": "World"}, "json")