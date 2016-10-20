import socket
from struct import *
import sys
import time
import binascii
import threading
from queue import Queue
from statistics import mean
from statistics import pstdev


packets_sent_queue = Queue()  # Used to "send" information from thread "Sending" to thread "Listening"


def to_NTP_format(unix_time):

    # https://docs.python.org/2/library/time.html#time.time > Gives number of seconds since Unix Epoch (0h Jan 1 1970)
    # https://tools.ietf.org/html/rfc868 > Gives number of seconds between Unix Epoch and 0h Jan 1 1900 (!)
    localtime = unix_time + 2208988800

    timestamp_integer_part = int(localtime)
    timestamp_fractional_part = localtime % 1  # FIXME: Take this as float for now. Need to change to NTP format

    # Return Bytes
    return pack('!I', timestamp_integer_part) + pack('!f', timestamp_fractional_part)


def from_NTP_format(timestamp):
    # FIXME: Treats fractional part as a float, for now. Need to actually implement NTP format...
    timestamp_integer_part, timestamp_fractional_part = unpack('! I f ', timestamp)
    return float(timestamp_integer_part) + timestamp_fractional_part

class Listening(threading.Thread):

    #samples_list = []  # Packet RTD of each sample

    def __init__(self, sock, dst_ip, dst_udp_port, tos=0):
        self.sock = sock
        self.dest_ip = dst_ip  # Added destination IP and Port in order to filter out unwanted packets.
        self.dest_udp_port = dst_udp_port
        self.tos = tos
        self.samples_list = []  # Packet RTD of each sample
        threading.Thread.__init__(self)

    def unauthenticated_response_packet(self, received_data):
        seq, time_int, time_fract, error_estimate, mbz_1, rcv_time_int, rcv_time_fract, \
        sender_seq, sender_time_int, sender_time_fract, sender_error, \
        mbz_2, sender_ttl = unpack('! I I I H H I I I I f H H B', received_data[:41])  # FIXME: sender_time_int as NTP

        if mbz_1 != 0 or mbz_2 != 0:
            print('Session-reflector is not setting both MBZ fields to zero.')

        # Return a dictionary. Keys have the same name as fields in https://tools.ietf.org/html/rfc5357#section-4.2.1
        packet_header = {'Sequence Number': seq, 'Timestamp': float(str(time_int)+'.'+str(time_fract)),
                         'Error Estimate': error_estimate,
                         'Receive Timestamp': float(str(rcv_time_int)+'.'+str(rcv_time_fract)),
                         'Sender Sequence Number': sender_seq,
                         'Sender Timestamp': float(sender_time_int)+sender_time_fract,
                         'Sender Error Estimate': sender_error, 'Sender TTL': sender_ttl}

        return packet_header

    def get_stats(self):
        round_trip_delay = 0.0
        st_dev = 0.0

        packets_rcved = len(self.samples_list)
        packets_sent = 0
        packet_loss = 0

        # Calculate statistical data: rtd is mean value whereas st_dev is the standard deviation of rtd
        if packets_rcved == 0:  # If I did not receive a singe TWAMP-Test packet
            round_trip_delay = 60.0
            st_dev = 0.0
        else:
            round_trip_delay = mean(self.samples_list)
            st_dev = pstdev(self.samples_list, round_trip_delay)


        # Get info about packets_sent by "Sending" thread
        while not packets_sent_queue.empty():
            queue_item = packets_sent_queue.get(block=False)
            #print(queue_item)
            packets_sent += 1

        if packets_sent == 0:
            print(self.getName() + ': I found no packets in Queue which is fishy!')


        #print(packets_rcved)
        #print(packets_sent)

        packet_loss = 1 - packets_rcved / packets_sent

        return packet_loss, round_trip_delay, st_dev

    def run(self):
        current_time = time.time() + 2208988800 # Initialise variable here so it is visible within the exception block.
        # Value will be overwritten in try block. (Unless not a single packet arrives)

        while True:
            try:
                received_data, addr = self.sock.recvfrom(2048)  # Receive buffer size is 2048 bytes

                # Uncomment following sentence for debug purposes only
                # print('Recvfrom ' + str(addr[0]) + ':' + str(addr[1]) + ' the message:' + str(received_data))

                if addr[0] != self.dest_ip or addr[1] != self.dest_udp_port:
                    print('Received packet from unexpected host ' + str(addr[0]) + ':' + str(addr[1])+'. Disregard it.')
                    continue

                header = self.unauthenticated_response_packet(received_data)
                #print(header['Sender Sequence Number'])

                if header['Sender Sequence Number'] < 1000000 * self.tos:
                    print('Received re-ordered packet with Sender Sequence Number', header['Sender Sequence Number'],
                          'which I will disregard.')
                    continue

                current_time = time.time() + 2208988800
                self.samples_list.append(current_time - header['Sender Timestamp'])

                # Uncomment following sentence for debug purposes only
                #print(header)

            except socket.timeout:
                packet_loss, round_trip_delay, st_dev = self.get_stats()

                # Print to terminal:
                # Here current_time is the "timestamp" of the last received packet
                # Print to terminal:
                print(time.strftime("%H:%M:%S", time.gmtime(current_time - 2208988800)), 'UTC >',
                      'Loss %:', format(100 * packet_loss, '.4g'),
                      ', RTD ms:', format(1000 * round_trip_delay, '.4g'),
                      '> st.dev ms:', format(1000 * st_dev, '.4g')
                      )

                print('\n'+self.getName()+': The test ended above as I received no data for 5 seconds.\n')
                break


class Sending(threading.Thread):

    def __init__(self, sock, dst_ip, dst_udp_port, tos=0, test_duration=60):
        self.sock = sock
        self.dest_ip = dst_ip
        self.dest_udp_port = dst_udp_port
        self.tos = tos
        self.test_duration = test_duration
        threading.Thread.__init__(self)

    def unauthenticated_test_packet(self, seq, padding=1400):  # https://tools.ietf.org/html/rfc4656#section-4.1.2
        # By default use padding of 1400 Bytes

        # Sequence field
        sequence_number = pack('!I', int(seq))  # Used ! for bits alignment "network" (= big-endian)

        # Timestamp field
        timestamp = to_NTP_format(time.time())

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
        packet_seq = 1000000 * self.tos
        test_sample = 0

        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.tos)  # Set IP ToS Byte

        while True:
            # Create Layer4 payload for the TWAMP Unauthenticated Test packet
            msg = self.unauthenticated_test_packet(packet_seq)

            # Send UDP packet
            self.sock.sendto(msg, (self.dest_ip, self.dest_udp_port))

            packets_sent_queue.put(packet_seq, block=False)  # Send this info to "Listening" thread

            time.sleep(0.100)  # Current thread will sleep for 100 msec

            packet_seq += 1
            test_sample += 1

            if test_sample == 10 * self.test_duration:  # Test sample increases every 100ms (due to sleep) so
                # this if statement defines Test runtime. Default value (60) equals to 1 minute runtime.
                break


# -- Main --
def Main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # AF_INET for IPv4 and SOCK_DGRAM for UDP

    # Set IP TTL to 255 according to https://tools.ietf.org/html/rfc4656#section-4.1.2
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)

    s.settimeout(5)  # Set timeout of 5 seconds to blocking operations such as recvfrom()

    s.bind(('192.168.1.38', 862))

    listener = Listening(s, '192.168.1.155', 862)
    sender = Sending(s, '192.168.1.155', 862, 3)

    listener.start()
    sender.start()

    listener.join()  # Main thread must will until the Listening thread is finished
    s.close()

if __name__ == '__main__':
    # session_sender.py is being executed as script
    Main()

