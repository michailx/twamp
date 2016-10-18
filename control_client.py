import socket
from struct import *
import sys
import time
import ipaddress


def server_greeting(received_data):
    (mode, ) = unpack('!I', received_data[12:16])  # get Mode field; bytes 12,13,14 and 15
    return mode


def set_up_response():
    mode = pack('!I', 1)
    rest_of_packet = pack('!20Q', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return mode + rest_of_packet


def server_start(received_data):
    accept = int(received_data[15])
    return accept


def request_tw_session(session_sender, session_reflector):
    # https://tools.ietf.org/html/rfc5357#section-3.5
    command_number = bytes([5])  # One Byte with the value of decimal 5
    ipvn = bytes([4])  # One Byte with value 4 for IPv4; also include the MBZ field
    conf_sender_receiver = pack('!H', 0)  # Both the Conf-Sender field and Conf-Receiver field MUST be set to 0
    num_of_schedule_slots = pack('!I', 0)  # the Number of Scheduled Slots and Number of Packets MUST be set to 0
    num_of_pkts = pack('!I', 0)
    sender_port = pack('!H', session_sender[1])  # This is the local UDP port at the session-sender (used by TWAMP-Test)
    # Right below is the remote UDP port at the session-reflector (used by TWAMP-Test):
    receiver_port = pack('!H', session_reflector[1])

    # According to https://tools.ietf.org/html/rfc5357#section-3.5 , I could have set these both to zero (0) since I am
    # using the same addresses for TWAMP-Test as I did with TWAMP-Control. Unfortunately this did not work with Cisco.
    # Therefore I just set them again... to be the same as TWAMP-Control.
    sender_address = bytes([int(x) for x in session_sender[0].split('.')] + [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    receiver_address = bytes([int(x) for x in session_reflector[0].split('.')] + [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    sid = pack('!QQ', 0, 0)  # the SID in the Request-TW-Session message MUST be set to 0
    padding_length = pack('!I', 1372)  # Session-Reflector shall add 1372 Bytes padding to its reponse packet

    # https://docs.python.org/2/library/time.html#time.time > Gives number of seconds since Unix Epoch (0h Jan 1 1970)
    # https://tools.ietf.org/html/rfc868 > Gives number of seconds between Unix Epoch and 0h Jan 1 1900 (!)
    localtime = time.time() + 2208988800

    # Start Time -> Time when the TWAMP-Test session is to be started (but not before Start-Sessions command is issued)
    start_time_integer_part = int(localtime)  # Start in zero (0) seconds from now
    start_time_fractional_part = int(str(localtime % 1)[2:11])  # Take 9 decimal places
    start_time = pack('!I', start_time_integer_part) + pack('!I', start_time_fractional_part)

    timeout_integer_part = 10  # Session-Reflector will reflect TWAMP-Test packets for 10 seconds after Stop-Sessions
    timeout_fractional_part = 0
    timeout = pack('!I', timeout_integer_part) + pack('!I', timeout_fractional_part)

    type_p_descriptor = pack('!I', 96)  # Ask Session-Reflector to mark TWAMP-test packets with CS3
    mbz = pack('!Q', 0)

    hmac = pack('!QQ', 0, 0)  # In open mode, the HMAC fields are unused and have the same semantics as MBZ fields

    msg = command_number + ipvn + conf_sender_receiver + num_of_schedule_slots + num_of_pkts + sender_port
    msg += receiver_port + sender_address + receiver_address + sid + padding_length + start_time + timeout
    msg += type_p_descriptor + mbz + hmac

    return msg


def accept_session(received_data):
    accept = received_data[0]
    (port, ) = unpack('!H', received_data[2:4])  # Bytes 2 and 3
    return accept, port


def start_sessions():
    command_number = bytes([2])  # One Byte with the value of decimal 2
    mbz = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # Fifteen Bytes of 0
    hmac = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # Sixteen Bytes of 0
    return command_number + mbz + hmac


def start_ack(received_data):
    accept = received_data[0]
    return accept


def stop_sessions():
    # https://tools.ietf.org/html/rfc5357#section-3.8
    command_number = bytes([3])  # One Byte with the value of decimal 2
    accept = bytes([0])
    mbz = pack('!H', 0)
    number_of_sessions = pack('!I', 1)  # I have only started one session
    mbz_hmac = pack('!QQQ', 0, 0, 0)
    return command_number + accept + mbz + number_of_sessions + mbz_hmac


# --- Main ---
# Limit the IP block of Servers / Session-Reflectors for security purposes ...
ALLOWED_SERVER_BLOCK = '192.168.0.0/16'
allowed_server_block = ipaddress.IPv4Network(ALLOWED_SERVER_BLOCK)

if len(sys.argv) == 3:
    print('\nYou have defined the Server / Session-Reflector ', sys.argv[1], 'and asked for the TWAMP-Test to last ',
          sys.argv[2], ' minutes.')

    target_ip = ipaddress.ip_address(sys.argv[1])
    test_duration_minutes = int(sys.argv[2])

    if target_ip not in allowed_server_block.hosts():
        print("Unfortunately the IPv4 address that you provided is not within allowed block "
              + ALLOWED_SERVER_BLOCK + '\n')
        sys.exit(1)
    elif test_duration_minutes <= 0:
        print("Test duration (minutes) has to an integer greater than zero (0). E.g. 1, 2, 3, 4, 5, etc\n")
        sys.exit(1)
else:
    print('\nThis script requires two (2) command-line arguments; the IPv4 address of the Server / Session-Reflector as'
          ' well as the TWAMP-Test duration (in minutes).\n')
    sys.exit(1)

CONTROL_CLIENT = ('192.168.1.38', 862)  # This is the local host
SESSION_SENDER = (CONTROL_CLIENT[0], 21337)
server = (str(sys.argv[1]), 862)
session_reflector = (server[0], 21337)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 96)  # Set IP ToS Byte to 96 (CS3). "The Server SHOULD use the DSCP of
# the Control-Client's TCP SYN in ALL subsequent packets on that connection as noted in:
# https://tools.ietf.org/html/rfc5357#section-3.1

s.settimeout(5)  # Set timeout of 5 seconds to blocking operations such as recv()

s.bind(CONTROL_CLIENT)
s.connect(server)


data = s.recv(1024)
#  https://tools.ietf.org/html/rfc4656#section-3.1
mode = server_greeting(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Server Greeting msg from ', server)
if mode != 1:
    print('[Server Greeting] This script only supports unauthenicated mode and as such it expected Mode to be 1.')
    print('However, it received mode value' + str(mode) + '.')
    s.close()
    sys.exit(1)


set_up_response_msg = set_up_response()
s.send(set_up_response_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Set-up-Response msg to ', server)


data = s.recv(1024)
accept = server_start(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Server-Start msg from ', server)
if accept != 0:
    print('[Server Start] The remote server is not willing to continue communication as the Accept field was ' +
          str(accept) + 'instead of zero (0)')
    s.close()
    sys.exit(1)


request_tw_session_msg = request_tw_session(SESSION_SENDER, session_reflector)
s.send(request_tw_session_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Request-TW-Session msg to ', server)


data = s.recv(1024)
accept, session_reflector_port = accept_session(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Accept-Session msg from ', server)
if accept != 0:
    print('[Accept Session] The remote server is not willing to continue communication as the Accept field was ' +
          str(accept) + 'instead of zero (0)')
    s.close()
    sys.exit(1)
elif session_reflector_port != session_reflector[1]:
    print('[Accept Session] The remote server cannot / will not create a TWAMP-test session on UDP port ' +
          str(session_reflector[1]) + ' but instead replied with ' + str(session_reflector_port) + '.\n Stopping ...')
    s.close()
    sys.exit(1)


start_sessions_msg = start_sessions()
s.send(start_sessions_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Start-Sessions msg to ', server)


data = s.recv(1024)
accept = start_ack(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Start-Ack msg from ', server)
if accept != 0:
    print('[Start Ack] The remote server is not willing to continue communication as the Accept field was ' +
          str(accept) + 'instead of zero (0)')
    s.close()
    sys.exit(1)
else:
    # --- Start TWAMP Test ---
    print('\n[TWAMP-Test] Starting UDP traffic; Session-Sender is', SESSION_SENDER, 'and Session-Reflector is ',
          session_reflector)
    from session_sender import Listening
    from session_sender import Sending
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # AF_INET for IPv4 and SOCK_DGRAM for UDP

    #  Set IP TTL to 255 according to https://tools.ietf.org/html/rfc4656#section-4.1.2
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
    sock.settimeout(5)  # Set timeout of 5 seconds to blocking operations such as recvfrom()
    sock.bind(SESSION_SENDER)
    # Using classes from file session_sender.py
    listener = Listening(sock, session_reflector[0], session_reflector[1])
    sender = Sending(sock, session_reflector[0], session_reflector[1], test_duration_minutes)
    listener.setName('TWAMP_TEST_SESSION_SENDER___LISTENING_THREAD')
    sender.setName('TWAMP_TEST_SESSION_SENDER___SENDING_THREAD')
    listener.start()
    sender.start()
    listener.join()  # This (main) thread must wait until the Listening thread is finished
    sock.close()
    print('[TWAMP-Test] Test has finished.\n')
    # --- End of Test ---


stop_sessions_msg = stop_sessions()
s.send(stop_sessions_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Stop-Sessions msg to ', server)

s.close()
