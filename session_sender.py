import socket
from struct import *
import sys
import time
import binascii
import threading


class Listening(threading.Thread):

    def __init__(self, sock, dst_ip, dst_udp_port):
        self.sock = sock
        self.dest_ip = dst_ip  # Added destination IP and Port in order to filter out unwanted packets.
        self.dest_udp_port = dst_udp_port
        threading.Thread.__init__(self)

    def unauthenticated_response_packet(self, received_data):
        seq, time_int, time_fract, error_estimate, mbz_1, rcv_time_int, rcv_time_fract, \
        sender_seq, sender_time_int, sender_time_fract, sender_error, \
        mbz_2, sender_ttl = unpack('! I I I H H I I I I I H H B', received_data[:41])

        if mbz_1 != 0 or mbz_2 != 0:
            print('Session-reflector is not setting both MBZ fields to zero.')

        # Return a dictionary. Keys have the same name as fields in https://tools.ietf.org/html/rfc5357#section-4.2.1
        packet_header = {'Sequence Number': seq, 'Timestamp': float(str(time_int)+'.'+str(time_fract)),
                         'Error Estimate': error_estimate,
                         'Receive Timestamp': float(str(rcv_time_int)+'.'+str(rcv_time_fract)),
                         'Sender Sequence Number': sender_seq,
                         'Sender Timestamp': float(str(sender_time_int)+'.'+str(sender_time_fract)),
                         'Sender Error Estimate': sender_error, 'Sender TTL': sender_ttl}

        return packet_header

    def aggregate_samples(self, samples_list, upper_bound):
        packet_loss = 0.0
        round_trip_delay = 0.0
        jitter = 0.0

        # Take care of packet reordering in the network
        samples_sorted = sorted(samples_list, key=lambda item: item[0])

        # len(samples_sorted) is the number of samples during this time window
        num_of_samples = len(samples_sorted)

        # samples_sorted[-1][0] is the highest Sender Sequence Number received during this time window
        highest_sender_seq_nbr = samples_sorted[-1][0]

        # samples_sorted[0][0] is the lowest Sender Sequence Number received during this time window
        lowest_sender_seq_nbr = samples_sorted[0][0]

        # Expected number of received packets during this window:  1 + upper_bound - lowest_sender_seq_nbr
        # Uppoer bound is the theoretical highest Sender SEQ number for this aggregation window
        # Calculate Packet loss:
        packet_loss = 1 - num_of_samples / (1 + upper_bound - lowest_sender_seq_nbr)

        # Calculate Delay:

        return num_of_samples, packet_loss, round_trip_delay, jitter

    def run(self):
        samples = []
        sample = (0, 0)
        start_time = time.time() + 2208988800
        current_time = start_time  # Initialise variable here so it is visible within the exception block. Value will
        # be overwritten in try block.

        print('Interval (sec) | Total number of rcv pkts | Packet loss (%) | Delay (msec) | Jitter (msec) |')

        while True:
            try:
                received_data, addr = self.sock.recvfrom(2048)  # Receive buffer size is 2048 bytes

                # Uncomment following sentence for debug purposes only
                # print('Recvfrom ' + str(addr[0]) + ':' + str(addr[1]) + ' the message:' + str(received_data))

                if addr[0] != self.dest_ip or addr[1] != self.dest_udp_port:
                    print('Received packet from unexpected host '+str(addr[0]) + ':' + str(addr[1])+'. Disregard it.')
                    continue

                header = self.unauthenticated_response_packet(received_data)

                current_time = time.time() + 2208988800

                sample = (header['Sender Sequence Number'], current_time - header['Sender Timestamp'])

                if current_time - start_time >= 15.0:
                    # I will exclude this newest sample from the aggregation. I will use the previous "sample" as upper
                    # bound. Maybe I already received it, maybe it was lost in transit. I need it to calc pkt loss.
                    num_of_samples, packet_loss, round_trip_delay, jitter = \
                        self.aggregate_samples(samples, sample[0]-1)

                    # Print to terminal:
                    print(format(current_time - start_time, '.4g') + ' | ' + str(num_of_samples) + ' | ' +
                          format(packet_loss*100, '.4g') + ' | ' + format(round_trip_delay*1000, '.4g') + ' | ' +
                          format(jitter*1000, '.4g') + ' | ')

                    # Clear lists
                    samples = []

                    # Set new start time
                    start_time = time.time() + 2208988800

                # Uncomment following sentence for debug purposes only
                #print(header)

                samples.append(sample)

            except socket.timeout:
                num_of_samples, packet_loss, round_trip_delay, jitter = \
                    self.aggregate_samples(samples, sample[0])

                # Print to terminal:
                # Here current_time is the "timestamp" of the last received packet
                print(format(current_time - start_time, '.5g') + ' | ' + str(num_of_samples) + ' | ' +
                      format(packet_loss * 100, '.3f') + ' | ' + format(round_trip_delay * 1000, '.4g') + ' | ' +
                      format(jitter * 1000, '.4g') + ' | ')

                print('\n'+self.getName()+': The tested ended above as I received no data for 5 seconds.\n')

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

            time.sleep(0.120)  # Current thread will sleep for 100 msec

            packet_seq += 1
            packet_ipp += 1
            if packet_ipp == 8:
                test_sample += 1  # Increment after 8 test pckts sent, with ToS: 0, 32, 64, 96, 128, 160, 192, 224
                packet_ipp = 0

            if test_sample == 60:  # Test sample increases every 800ms (due to sleep) so this check defines run time
                # Equals 60 for 1 minute
                break


# -- Main --
def Main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # AF_INET for IPv4 and SOCK_DGRAM for UDP

    # Set IP TTL to 255 according to https://tools.ietf.org/html/rfc4656#section-4.1.2
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)

    s.settimeout(5)  # Set timeout of 5 seconds to blocking operations such as recvfrom()

    s.bind(('192.168.1.38', 862))

    listener = Listening(s, '192.168.1.155', 862)
    sender = Sending(s, '192.168.1.155', 862)

    listener.start()
    sender.start()

    listener.join()  # Main thread must will until the Listening thread is finished
    s.close()

if __name__ == '__main__':
    # session_sender.py is being executed as script
    Main()

