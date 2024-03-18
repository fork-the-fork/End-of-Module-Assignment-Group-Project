"""
This file performs the unit tests on the client-server code.
"""

import unittest

from server import extract_bits, initialize_server_context
from client import ClientSession
import client
import subprocess
import os
from utils import paths
from pathlib import Path
import cryptography
import configparser

class BitExtraction(unittest.TestCase):
    """
    Test bit extraction functionaility, ensuring the extract_bits is able
    to extract the bit values of multiple integers between 0 - 255.
    """
    def test_extract_bits_a(self):
        self.assertEqual(extract_bits(100, 3, 3), 1)
        #01100100
        #   | |
    
    def test_extract_bits_b(self):
        self.assertEqual(extract_bits(0, 1, 7), 0)
        #00000000
        #|      |
    
    def test_extract_bits_c(self):
        self.assertEqual(extract_bits(255, 7, 1), 1)
        #11111111
        #       |

    def test_extract_bits_d(self):
        self.assertEqual(extract_bits(100, 3, 3), 1)
        #01100100
        #   | |
    
    def test_extract_bits_e(self):
        self.assertEqual(extract_bits(65, 1, 7), 65)
        #01000001
        # |     |
    
    def test_extract_bits_f(self):
        self.assertEqual(extract_bits(10, 6, 2), 2)
        #00001010
        #     | |

class ServerConfiguration(unittest.TestCase):
    """
    Test server configuration functionaility, ensuring the extract_bits is able
    to extract the bit values of multiple integers between 0 - 255.
    """
    def setUp(self):
        self.default_config = configparser.ConfigParser()
        server_config_path = paths.expand_path("./etc/default.ini")
        self.default_config.read(server_config_path)
            
    def test_reading_default_config(self):
        parsed_config = initialize_server_context(self.default_config)
        self.assertIsInstance(parsed_config["tcp_host"], str)
        self.assertIsInstance(parsed_config["tcp_port"], int)
        self.assertIsInstance(parsed_config["encryption_enabled"], bool)
        self.assertIsInstance(parsed_config["symmetric_key_file"], Path)
        self.assertIsInstance(parsed_config["stream_output"], bool)
        self.assertIsInstance(parsed_config["file_output_enabled"], bool)
        self.assertIsInstance(parsed_config["file_output_directory"], Path)
        self.assertIsInstance(parsed_config["dictionary_output_format"], str)
        self.assertIsInstance(parsed_config["file_name_format"], str)
        self.assertIsInstance(parsed_config["print_output_enabled"], bool)
        self.assertIsInstance(parsed_config["pickle_enabled"], bool)
        self.assertIsInstance(parsed_config["symmetric_key"], cryptography.fernet.Fernet)

class ClientServerFunctions(unittest.TestCase):
    """
    Testing file transfers and encyrption functionality for client interacting with server.
    """
    def setUp(self):
        # Start the server as a non-blocking process
        server_py = str(paths.expand_path("./src/server.py").absolute())
        self.server_proc = subprocess.Popen(["python", server_py])
        
        # Initialise a client
        self.client = ClientSession()

        # Output file directory
        self.output_file_directory = str(paths.expand_path("./output").absolute())
    
    def tearDown(self):
        self.server_proc.kill()
        self.server_proc.wait()
    
    def _determine_directory_growth(self, func, *args, **kwargs):
        before = len(os.listdir(self.output_file_directory))
        resp = func(*args, **kwargs)
        after = len(os.listdir(self.output_file_directory))
        return resp, (after - before)
    
    def test_connect_to_server(self):
        self.client.open()
        self.client.close()
    
    def test_encryption_non_explicit(self):
        new_client = ClientSession(encryption_key_file="./etc/secret/example.key")
        new_client.open()
        new_client.close()
    
    def test_encryption_explicit(self):
        self.client.open()
        self.client.enable_encryption("./etc/secret/example.key")
        self.client.close()
    
    def test_large_dictionary_transfer_xml(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_dictionary, {f"A{i}": str(i+1) for i in range(10000)}, "xml")
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()

    def test_large_dictionary_transfer_json(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_dictionary, {f"A{i}": str(i+1) for i in range(10000)}, "json")
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()
    
    def test_large_dictionary_transfer_binary(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_dictionary, {f"A{i}": str(i+1) for i in range(10000)}, "binary")
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()

    def test_small_dictionary_transfer_xml(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_dictionary, {f"A{i}": str(i+1) for i in range(2)}, "xml")
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()

    def test_small_dictionary_transfer_json(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_dictionary, {f"A{i}": str(i+1) for i in range(2)}, "json")
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()
    
    def test_small_dictionary_transfer_binary(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_dictionary, {f"A{i}": str(i+1) for i in range(2)}, "binary")
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()
    
    def test_large_text_message_transfer_unencrypted(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_text, "Hello " * 10000)
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()
    
    def test_small_text_message_transfer_unencrypted(self):
        self.client.open()
        resp, growth = self._determine_directory_growth(self.client.send_text, "Howdy " * 5)
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()

    def test_large_text_message_transfer_encrypted(self):
        self.client.open()
        self.client.enable_encryption("./etc/secret/example.key")
        resp, growth = self._determine_directory_growth(self.client.send_text, "Hola " * 10000)
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()

    def test_small_text_message_transfer_encrypted(self):
        self.client.open()
        self.client.enable_encryption("./etc/secret/example.key")
        resp, growth = self._determine_directory_growth(self.client.send_text, "Hi " * 10)
        self.assertGreater(growth, 0)
        self.assertEqual(resp, 0)
        self.client.close()
    
    def test_text_file_transfer_unencrypted(self):
        self.client.open()
        self.client.send_text_file("./.gitignore")
        self.client.close()
    
    def test_text_file_transfer_encrypted(self):
        self.client.open()
        self.client.enable_encryption("./etc/secret/example.key")
        self.client.send_text_file("./.gitignore")
        self.client.close()

    def test_client_demo(self):
        resp, growth = self._determine_directory_growth(client.main)
        self.assertEqual(growth, 6)
    
    def test_client_open_close(self):
        self.client.open()
        self.client.close()

if __name__=="__main__":
    unittest.main()
