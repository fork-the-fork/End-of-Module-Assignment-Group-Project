"""
The utils.encryption module contains utilities to support file encryption.
"""
import os
from cryptography.fernet import Fernet

def generate_key_and_save_to_file(filename):
    # check key exist before generating
    if os.path.exists(filename):
        with open(filename, "rb") as key_file:
            _key = key_file.read()
        return _key

    _key = Fernet.generate_key()
    with open(filename, "wb") as key_file:
        key_file.write(_key)
    return _key



