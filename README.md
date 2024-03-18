# End-of-Module-Assignment: Group-Project

### End_Module_Assignment_Group B
**Members: Alhanouf Aljunaydi, Azmi Chahal, Dang Dong, Thomas Lundie, Adhir Soechit**

### Overview
This project implements a client-server network where the client can send dictionary data or text files to the server. The client can specify the pickling format for the dictionary data and also choose to encrypt the data before sending.

* Build a simple client and server network.

* Create a dictionary, populate it, serialize it and send it to server. With dictionary, support the following serialization (pickling) formats: Binary, JSON and XML. 

* Create a text file and send it to server.

* The server needs to support encrypted contents.

* The server will have a configurable option to print the content to the screen or to be a file


### Architecture
        +-------------------+           +-------------------+
        |                   |           |                   |
        |      Client       |           |      Server       |
        |                   |           |                   |
        +-------------------+           +-------------------+
                 |                               |
                 |         TCP Session           |
                 | ----------------------------> |
                 |                               |
                 |     Transfer  Instruction     |
                 | ----------------------------> |
                 |                               |
                 |           Meta Data           |
                 | ----------------------------> |
                 |                               |
                 |                               |
                 |   File via 65535 Byte Chunks  |
                 | ----------------------------> |
                 |                               |
                 |         Success Status        |
                 | <---------------------------- |

The client and server use a bespoke application layer protcol to communicate. The protocol is structured as follows:

**Operation Byte**
* Client Instruction (4-bits)
    * TRANSFER = 0
    * END = 1
    * 16 possible operations supported for future expansion
* Initial Operation (1-bit)
    * Whether or not this packet is the first for this particular operation
* Final Operation (1-bit)
    * Whether or not this packet is the final for this particular operation.

**Meta Byte**
* File Type (3-bits)
    * TEXT = 0
    * DICTIONARY = 1
* Serialization Type (3-bits)
    * TEXT = 0
    * BINARY = 1
    * JSON = 2
    * XML = 3
* Encrypted (1-bit)
    * Whether or not the payload is symmetrically encrypted with the Fernet encryption method 

**Payload**
* Pre-fixed with a two-byte big-endian integer.

### Unit test

```bash
# Execute the module directly using python:
python ./src/unittest.py
```
### License
Distributed under the MIT License. See LICENSE.txt for more information.

### Instructions:

#### Running the Server
```bash
# Update the config.ini file in ./etc
[listening]
host = # IP/Host to bind the server to
port = # TCP port to bind the server to

[encryption]
enabled = # Does the server support encryption
symmetric_key_file = # Where is the symmetric key for encryption

[output]
stream_output = # If the file spans multiple packets, should it be streamed in chunks or in one go
file_output_enabled = # Does the server output to a file
file_output_format = # File output format "original" or "json"
file_output_directory = # Directory to output files to
file_name_format = # File name template (supports: {source}, {timestamp} and {format})
print_output_enabled = #  Does the server print uploads to screen

[serialization]
pickle_enabled = # Is pickled enabled? Disabled by default as it presents a security risk.
```

```bash
# Start the server
python server.py
```

#### Running the Client
```bash
# Run a demo sending a dictionary and encrypted client.
python client.py

# Or dynamically use the client
import client
client = ClientSession()
client.open(host="127.0.0.1")
client.send_dictionary({"Example": "dict"}, "xml"})
client.send_text("Example Message")
client.close()
```