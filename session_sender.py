import socket
from struct import *
import sys
import time
import binascii

def unauthenticated_test_packet(seq):  # https://tools.ietf.org/html/rfc4656#section-4.1.2
    layer_4_payload = 'temp'  # Payload of the UDP packet
    sequence_number = seq

    # Timestamp field
    localtime = time.time() + 2208988800
    # https://docs.python.org/2/library/time.html#time.time > Gives number of seconds since Unix Epoch (0h Jan 1 1970)
    # https://tools.ietf.org/html/rfc868 > Gives number of seconds between Unix Epoch and 0h Jan 1 1900 (!)
    timestamp_integer_part = int(localtime)
    timestamp_fractional_part = int(str(localtime % 1)[2:11])  # Take 9 decimal places
    timestamp = pack('>I', timestamp_integer_part) + pack('>I', timestamp_fractional_part)

    print (localtime)
    print (timestamp_integer_part)
    print (timestamp_fractional_part)

    layer_4_payload = timestamp
    print(binascii.hexlify(layer_4_payload))
    return layer_4_payload

# IP details of session-REFLECTOR:
dest_ip = '192.168.1.1'
dest_udp_port = 862  # Well-known port for TWAMP Control (RFC 5357)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # AF_INET for IPv4 and SOCK_DGRAM for UDP

# Create Layer4 playload for the TWAMP Unauthenticated Test packet
MESSAGE = unauthenticated_test_packet(0)

# Send UDP packet
s.sendto(MESSAGE, (dest_ip, dest_udp_port) )


s.close()  # Close socket
sys.exit(0)  # Exit script
