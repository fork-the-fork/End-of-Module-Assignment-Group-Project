import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 6868
s.connect((host,port))

messages = ["Hello", "WORLD"]
message_count = len(messages)

for message_sel in range(message_count):
    message = messages[message_sel]
    final = 0
    if message_sel == 0:
        flow_control = 1
    elif message_sel < message_count - 1:
        flow_control = 2
    else:
        flow_control = 3
        final = 1
    
    status = 0

    # Op Byte
    my_bytes = (flow_control << 5 | status << 2 | final << 1).to_bytes(1, "big")

    # Meta Byte
    data_type = 0 << 5
    serial_format = 0 << 2
    encrypted = 0 << 1

    my_bytes += (data_type | serial_format | encrypted).to_bytes(1, "big")

    my_bytes += len(message).to_bytes(2, "big")
    my_bytes += message.encode("utf-8")
    print(' '.join(f'{x:08b}' for x in my_bytes))
    s.send(my_bytes)
