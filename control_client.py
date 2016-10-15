import socket
from struct import *
import sys
import time


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
    receiver_port = pack('!H', session_reflector[1])  # This is the remote UDP port at the session-reflector (used by TWAMP-Test)
    sender_address = pack('!QQ', 0, 0)  # Addresses MAY be 0 in case TWAMP-Test shall use the same as TWAMP-Control did
    receiver_address = pack('!QQ', 0, 0)
    sid = pack('!QQ', 0, 0)  # the SID in the Request-TW-Session message MUST be set to 0
    padding_length = pack('!I', 0)  # TEMP

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
    two = bytes([2])  # One Byte with the value of decimal 2
    mbz = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # Fifteen Bytes of 0
    hmac = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # Sixteen Bytes of 0
    return two + mbz + hmac


def start_ack(received_data):
    accept = received_data[0]
    return accept

# --- Main ---
CONTROL_CLIENT = ('192.168.1.38', 862)
SESSION_SENDER = (CONTROL_CLIENT[0], 21337)
SERVER = ('192.168.1.155', 862)
SESSION_REFLECTOR = (SERVER[0], 21337)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 96)  # Set IP ToS Byte to 96 (CS3)
s.settimeout(5)  # Set timeout of 5 seconds to blocking operations such as recvfrom()

s.bind(CONTROL_CLIENT)
s.connect(SERVER)


data = s.recv(1024)
#  https://tools.ietf.org/html/rfc4656#section-3.1
mode = server_greeting(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Server Greeting msg from ', SERVER)
if mode != 1:
    print('[Server Greeting] This script only supports unauthenicated mode and as such it expected Mode to be 1.')
    print('However, it received mode value' + str(mode) + '.')
    s.close()
    sys.exit(1)


set_up_response_msg = set_up_response()
s.send(set_up_response_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Set-up-Response msg to ', SERVER)


data = s.recv(1024)
accept = server_start(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Server-Start msg from ', SERVER)
if accept != 0:
    print('[Server Start] The remote server is not willing to continue communication as the Accept field was ' +
          str(accept) + 'instead of zero (0)')
    s.close()
    sys.exit(1)


request_tw_session_msg = request_tw_session(SESSION_SENDER, SESSION_REFLECTOR)
s.send(request_tw_session_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Request-TW-Session msg to ', SERVER)


data = s.recv(1024)
accept, session_reflector_port = accept_session(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Accept-Session msg from ', SERVER)
if accept != 0:
    print('[Accept Session] The remote server is not willing to continue communication as the Accept field was ' +
          str(accept) + 'instead of zero (0)')
    s.close()
    sys.exit(1)
elif session_reflector_port != SESSION_REFLECTOR[1]:
    print('[Accept Session] The remote server cannot / will not create a TWAMP-test session on UDP port ' +
          str(SESSION_REFLECTOR[1]) + ' but instead replied with ' + str(session_reflector_port) + '.\n Stopping ...')
    s.close()
    sys.exit(1)


start_sessions_msg = start_sessions()
s.send(start_sessions_msg)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' sent Start-Sessions msg to ', SERVER)


data = s.recv(1024)
accept = start_ack(data)
print('[TWAMP-Control] Control-Client ', CONTROL_CLIENT, ' received Start-Ack msg from ', SERVER)
if accept != 0:
    print('[Start Ack] The remote server is not willing to continue communication as the Accept field was ' +
          str(accept) + 'instead of zero (0)')
    s.close()
    sys.exit(1)


s.close()
