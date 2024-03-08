import socket
import sys
from threading import Thread

class InvalidHeader(Exception):
    """The server sent an invalid header."""


def extract_bits(int_byte, pos, count):
    # Right shift the number by p-1 bits to get the desired bits at the rightmost end of the number
    shifted_number = int_byte >> 8 - pos - count

    # Mask the rightmost k bits to get rid of any additional bits on the left
    mask = (1 << count) - 1
    return shifted_number & mask

    # END

TCP_IP = 'localhost'
TCP_PORT = 6868
BUFFER_SIZE = 1024

class ClientThread(Thread):

    def __init__(self,ip,port,sock,handler):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock
        #print " New thread started for "+ip+":"+str(port)
        self.flow = None
        self.client_status = None
        self.data_type = None
        self.serialize_format = None
        self.encrypted = None
        self.transfer_size = None
    
    def process_operation_byte(self, op_byte):

        flow = extract_bits(op_byte, 0, 3)
        if flow == 1:
            self.flow = "INIT"
        elif flow == 2:
            self.flow = "CONT"
        elif flow == 3:
            self.flow = "END"
        else:
            raise InvalidHeader("Flow control")
        
        status = extract_bits(op_byte, 3, 3)
        if status == 0:
            self.client_status = "OK"
        else:
            self.client_status = "ERROR"

        self.final = (op_byte >> 1) & 1

    def process_header(self, header):
        # Process header
        operation_byte, meta_byte = header[:2]
        # Operation byte controls flow of data transfer
        self.process_operation_byte(operation_byte)
        if self.flow != "END":
            self.transfer_size = int.from_bytes(header[2:], "big")
        
            if self.flow == "INIT":
                # INIT
                self.data_type = extract_bits(meta_byte, 0, 3)
                self.serialize_format = extract_bits(meta_byte, 3, 3)
                self.encrypted = (meta_byte >> 1) & 1
                self.transfer_size = int.from_bytes(header[2:], "big")
            
            elif self.flow == "CONT":
                # CONT
                self.transfer_size = int.from_bytes(header[2:], "big")
    
    def run(self):
        while True:
            try:
                self.session_controller()
            except InvalidHeader:
                pass

    def session_controller(self):
        header = bytes()
        payload = bytes()
        remaining_header = 4
        # Recieve bytes
        while remaining_header > 0:
            buffer = self.sock.recv(1024, socket.MSG_WAITALL)
            if buffer:
                header += buffer[:4]
                remaining_header = 4 - len(header)
                payload += buffer[4:]
        
        self.process_header(header)
        
        if self.flow == "END":
            self.sock.close()
            return False
        
        while len(payload) < self.transfer_size:
            buffer = self.sock.recv(1024,  socket.MSG_WAITALL)
            if buffer:
                payload += buffer
        
        if self.data_type == 0:
            # Text File
            if self.serialize_format == 0:
                handler.write(buffer.decode("utf-8"))
        
        handler.flush()

server_mode = "PRINT"
server_write = "CONTINUOUS"
# sever_mode = "SAVE"

class UploadHandler():
    
    def __init__(self):
        self.buffer = ""
        if server_write == "END":
            self.continuous = False
        elif server_write == "CONTINUOUS":
            self.continuous = True

        if server_mode == "PRINT":
            self.stream = sys.stdout
        else:
            self.stream = open("C:\Temp\hello.txt", "w")
    
    def write(self, string):
        if self.continuous:
            self.stream.write(string)
        else:
            self.buffer += string
    
    def flush(self):
        if self.continuous:
            self.stream.flush()
        else:
            self.stream.write(self.buffer)
            self.stream.flush()

handler = UploadHandler()

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