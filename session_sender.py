import socket
from struct import *
import sys
import time
import binascii
import threading


class Listening(threading.Thread):

    def __init__(self, sock):
        self.sock = sock
        threading.Thread.__init__(self)

    def run(self):
        while True:

            try:
                received_data, addr = s.recvfrom(2048)  # Receive buffer size is 2048 bytes

                # Uncomment following sentence for debug purposes only
                # print('Received from ' + addr[0] + ' the message: ' + str(received_data))
                print('recvfrom ' + str(addr[0]) + ':' + str(addr[1]) + ' the message (exl padding): ')



            except socket.timeout:
                print('I have not received any data for the last 10 seconds. Stopping thread execution...')
                break


class Sending(threading.Thread):

    def __init__(self, sock, dst_ip, dst_udp_port):
        self.sock = sock
        self.dest_ip = dst_ip
        self.dest_udp_port = dst_udp_port
        threading.Thread.__init__(self)

    def unauthenticated_test_packet(self, seq, padding=1400):  # https://tools.ietf.org/html/rfc4656#section-4.1.2
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
        # print('\nSequence: '+str(seq)+' - Layer 4 payload (in hex): '+binascii.hexlify(layer_4_payload)+'\n')

        return layer_4_payload

    def run(self):
        # While loop
        packet_seq = 0
        packet_ipp = 0
        test_sample = 0
        while True:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, packet_ipp * 32)  # Set IP ToS Byte

            # Create Layer4 payload for the TWAMP Unauthenticated Test packet
            msg = self.unauthenticated_test_packet(packet_seq)

            # Send UDP packet
            self.sock.sendto(msg, (self.dest_ip, self.dest_udp_port))

            time.sleep(1)  # Current thread will sleep for 1 second

            packet_seq += 1
            packet_ipp += 1
            if packet_ipp == 8:
                test_sample += 1  # Increment after 8 test pckts sent, with ToS: 0, 32, 64, 96, 128, 160, 192, 224
                packet_ipp = 0

            if test_sample == 8:  # Test sample increases every 8 seconds (due to sleep) so this check defines run time
                # Equals 38 for 5 minutes
                # Equals 8 for 1 minute
                break


# -- Main --

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # AF_INET for IPv4 and SOCK_DGRAM for UDP

# Set IP TTL to 255 according to https://tools.ietf.org/html/rfc4656#section-4.1.2
s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)

s.settimeout(10)  # Set timeout of 10seconds to blocking operations such as recvfrom()

s.bind(('192.168.1.38', 862))

listener = Listening(s)
sender = Sending(s, '192.168.1.155', 862)

listener.start()
sender.start()

listener.join()  # Main thread must will until the Listening thread is finished
s.close()
sys.exit(0)  # Exit script
