import socket
from struct import *
import sys
import time
import binascii


def unauthenticated_test_packet(seq, padding=1400):  # https://tools.ietf.org/html/rfc4656#section-4.1.2
    # By default use padding of 1400 Bytes

    # Sequence field
    sequence_number = pack('!I', int(seq))  # Used ! for bits alignment "network" (= big-endian)

    # Timestamp field
    localtime = time.time() + 2208988800
    # https://docs.python.org/2/library/time.html#time.time > Gives number of seconds since Unix Epoch (0h Jan 1 1970)
    # https://tools.ietf.org/html/rfc868 > Gives number of seconds between Unix Epoch and 0h Jan 1 1900 (!)
    timestamp_integer_part = int(localtime)
    timestamp_fractional_part = int(str(localtime % 1)[2:11])  # Take 9 decimal places
    timestamp = pack('!I', timestamp_integer_part) + pack('!I', timestamp_fractional_part)

    # Error Estimate field
    error_estimate = pack('!H', 32769)  # Binary 1000000000000001 (Decimal 32769)

    # Packet padding all-zeros, in Bytes
    packet_padding = padding * pack('!B', 0)

    # Payload of the UDP packet is 14 Bytes plus padding Bytes
    layer_4_payload = sequence_number + timestamp + error_estimate + packet_padding

    # Uncomment following sentence for debug purposes only
    print('\nSequence: '+str(seq)+' - Layer 4 payload (in hex): '+binascii.hexlify(layer_4_payload)+'\n')

    return layer_4_payload


# IP details of session-REFLECTOR:
dest_ip = '192.168.1.155'
dest_udp_port = 862  # Well-known port for TWAMP Control (RFC 5357)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # AF_INET for IPv4 and SOCK_DGRAM for UDP

# Set IP TTL to 255 according to https://tools.ietf.org/html/rfc4656#section-4.1.2
s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)

# Create Layer4 payload for the TWAMP Unauthenticated Test packet
MESSAGE = unauthenticated_test_packet(1338)

# Send UDP packet
s.sendto(MESSAGE, (dest_ip, dest_udp_port) )


s.close()  # Close socket
sys.exit(0)  # Exit script
