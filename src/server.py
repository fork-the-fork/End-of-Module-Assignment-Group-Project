import socket
from threading import Thread

class InvalidHeader(Exception):
    """The server sent an invalid header."""

def extract_bits(byte, pos, count):
    # Right shift the number by p-1 bits to get the desired bits at the rightmost end of the number
    shifted_number = byte >> (8 - pos - 1)
 
    # Mask the rightmost k bits to get rid of any additional bits on the left
    mask = (1 << count) - 1
    return shifted_number & mask



    # END

TCP_IP = 'localhost'
TCP_PORT = 6868
BUFFER_SIZE = 1024

""" tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((TCP_IP, TCP_PORT))
print("HI")
tcpsock.listen(5)
print("Howdy")
c_sock, _ = tcpsock.accept()
print("HI")
 """
class ClientThread(Thread):

    def __init__(self,ip,port,sock):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock
        #print " New thread started for "+ip+":"+str(port)
        self.flow = None
        self.data_type = None
        self.serialize_format = None
        self.encrypted = None
        self.transfer_size = None

    def process_header(self, header):
        # Process header
        operation_byte, meta_byte = header[:2]

        # Flow control
        flow = extract_bits(operation_byte, 0, 4)
        status = extract_bits(operation_byte, 4, 4)
        if flow == 1:
            self.flow = "INIT"
        elif flow == 2:
            self.flow = "CONT"
        elif flow == 3:
            self.flow = "END"
        else:
            raise InvalidHeader("Flow control")
        
        if self.flow == "INIT":
            # INIT
            self.data_type = extract_bits(meta_byte, 0, 3)
            self.serialize_format = extract_bits(meta_byte, 3, 3)
            self.encrypted = (meta_byte >> 7) & 1
            self.transfer_size = int.from_bytes(header[2:4], "little")
        
        elif self.flow == "CONT":
            # CONT
            self.transfer_size = int.from_bytes(header[2:4], "little")
    
    def run(self):
        while True:
            try:
                self.packet_iteration()
            except InvalidHeader:
                pass

    def packet_iteration(self):
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
        
        while True:
            buffer = self.sock.recv(1024)
            if not buffer:
                payload += buffer
                if len(payload) == self.transfer_size:
                    break
        
        if self.data_type == 0:
            # Text File
            print(repr(payload))

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((TCP_IP, TCP_PORT))
threads = []

while True:
    tcpsock.listen(5)
    #print "Waiting for incoming connections..."
    (conn, (ip,port)) = tcpsock.accept()
    #print 'Got connection from ', (ip,port)
    newthread = ClientThread(ip,port,conn)
    newthread.start()
    threads.append(newthread)

for t in threads:
    t.join()