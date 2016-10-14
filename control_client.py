import socket
from struct import *
import sys


def server_greeting(received_data):
    (mode, ) = unpack('!I', received_data[12:16])  # get Mode field; bytes 12,13,14 and 15
    return mode


def set_up_response():
    mode = pack('!I', 1)
    rest_of_packet = pack('!20Q', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return mode + rest_of_packet


def server_start(received_data):
    accept = int(received_data[15])
    print(accept)
    return accept


# --- Main ---

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 96)  # Set IP ToS Byte to 96 (CS3)
s.settimeout(5)  # Set timeout of 5 seconds to blocking operations such as recvfrom()

s.bind(('192.168.1.38', 862))
s.connect(('192.168.1.155', 862))

#s.send(MESSAGE)

data = s.recv(1024)
#  https://tools.ietf.org/html/rfc4656#section-3.1
mode = server_greeting(data)
if mode != 1:
    print('[Server Greeting] This script only supports unauthenicated mode and as such it expected Mode to be 1.')
    print('However, it received mode value' + str(mode) + '.')
    s.close()
    sys.exit(1)


set_up_response_msg = set_up_response()
s.send(set_up_response_msg)


data = s.recv(1024)
accept = server_start(data)
if accept != 0:
    print('[Server Start] The remote server is not willing to continue communication as the Accept field was ' + accept
          + 'instead of zero (0)')
    s.close()
    sys.exit(1)

s.close()
