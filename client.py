import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 6868
s.connect((host,port))

sixteen = 16
zero = 0
two = 2
my_bytes = sixteen.to_bytes(1, "little")
my_bytes += zero.to_bytes(2, "little")
my_bytes += two.to_bytes(1, "little")
my_bytes += b"YO"
print(' '.join(f'{x:08b}' for x in my_bytes))
s.send(my_bytes)
