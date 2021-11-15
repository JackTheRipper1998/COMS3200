import math
import socket
import struct
import sys
import traceback
import os.path
import threading
import time


LOCAL_HOST = "127.0.0.1"
RECV_SIZE = 4096
TIME_OUT = 5

FLAG = 0

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
QUERY = 0x06
AVAILABLE = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00


def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def int_to_str(integer, size):
    return integer.to_bytes(size, byteorder='big').decode("UTF-8")


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def calculate_distance(x1, y1, x2, y2):
    a = pow(x1 - x2, 2)
    b = pow(y1 - y2, 2)
    c = pow(x1, 2)
    d = pow(y1, 2)
    distance = pow(a + b, 0.5) + pow(c + d, 0.5)
    return math.floor(distance)


class LocalSwitch:
    def __init__(self, len_ip, location, output=sys.stdout, debug_level=1):
        self.len_ip = len_ip
        self.my_ip = len_ip.split('/')[0]
        self.my_cidr = len_ip.split('/')[1]
        self.location = location
        self.assigned_ip = None
        self._connect_info = (LOCAL_HOST, 0)
        self._serv_info = {}    # ser port: (ser IP, distance)
        self._client_info = {}  # assigned IP:(client IP, client port)
        self._socket = None
        self._tcp_socket = None
        self.pkt = b''
        self._output = output
        self._debug_level = debug_level
        self._start_time = time.time()

    def connected(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind(self._connect_info)
            return True
        except socket.error as err:
            print("Error encountered when opening socket:\n", err)
            return False

    def create_connection(self):
        print(self._socket.getsockname()[1])
        sys.stdout.flush()
        t = threading.Thread(target=self.greeting)
        t.start()

    def greeting(self):
        while True:

            if self.pkt:
                try:
                    # receive UDP data and address
                    data, addrs = self._socket.recvfrom(RECV_SIZE)
                except socket.timeout:
                    # self.resend_packet(addrs)
                    continue
            else:
                data, addrs = self._socket.recvfrom(RECV_SIZE)

            source_ip = int.from_bytes(data[:4], byteorder='big')
            des_ip = int.from_bytes(data[4:8], byteorder='big')
            reserved = int.from_bytes(data[8:11], byteorder='big')
            mode = int.from_bytes(data[11:12], byteorder='big')
            if (mode == DATA):
                message = data[12:]
            else:
                assigned_ip = int.from_bytes(data[12:16], byteorder='big')

            if (mode == DISCOVERY):
                give_ip = self.my_ip[:-1] + str(len(self._client_info) + 2)
                self.send_greeting(addrs, give_ip, OFFER)
            elif (mode == REQUEST):
                self.send_greeting(addrs, assigned_ip, ACKNOWLEDGE)
            elif (mode == DATA):
                flag = 0
                for key, value in self._client_info.items():
                    if value[1] == des_ip:
                        self.pkt = struct.pack('!LLL', ip_to_int(self.my_ip), des_ip, QUERY)
                        key.send(self.pkt)
                        # key.recvfrom(RECV_SIZE)
                        self.pkt = struct.pack('!LLL', source_ip, des_ip, DATA) + message
                        key.send(self.pkt)
                        flag = 1
                if (flag == 0):
                    for key, value in self._serv_info.items():
                        self.pkt = struct.pack('!LLL', value[0], value[1], QUERY)
                        key.send(self.pkt)
                        # try:
                        #     key.recvfrom(RECV_SIZE)
                        # except socket.timeout:
                        #     print(111)
                        #     sys.stdout.flush()
                        self.pkt = struct.pack('!LLL', source_ip, des_ip, DATA) + message
                        key.send(self.pkt)

    def send_greeting(self, addrs, assign_ip, mode):
        self.pkt = self.create_greeting_pkt(addrs, self.my_ip, assign_ip, mode, self._client_info)
        self._socket.sendto(self.pkt, addrs)



    @staticmethod
    def create_greeting_pkt(addrs, source_ip, assign_ip, mode, client_info):
        if (mode == OFFER):
            return struct.pack('!LLLL', ip_to_int(source_ip), 0, mode, ip_to_int(assign_ip))
        elif (mode == ACKNOWLEDGE):
            client_info[int_to_ip(assign_ip)] = addrs
            return struct.pack('!LLLL', ip_to_int(source_ip), assign_ip, mode, assign_ip)

    def recv_input(self):
        while True:
            try:
                buffer = input("> ").split()
            except EOFError:
                break
            if ((len(buffer) != 2) or (buffer[0] != "connect")):
                continue
            port = int(buffer[1])
            t = threading.Thread(target=self.tcp_connect, args=(port, ))
            t.start()

    def tcp_connect(self, port):
        socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_send.connect((LOCAL_HOST, port))
        self.send_greeting_send(0, 0, DISCOVERY, socket_send)
        while True:
            if self.pkt:
                try:
                    data = socket_send.recv(RECV_SIZE)
                except socket.timeout:
                    # self.resend_packet(addrs)
                    continue
            else:
                data = socket_send.recv(RECV_SIZE)

            source_ip = int.from_bytes(data[:4], byteorder='big')
            des_ip = int.from_bytes(data[4:8], byteorder='big')
            reserved = int.from_bytes(data[8:11], byteorder='big')
            mode = int.from_bytes(data[11:12], byteorder='big')
            if (mode == LOCATION):
                x = int.from_bytes(data[12:14], byteorder='big')
                y = int.from_bytes(data[14:16], byteorder='big')
            elif (mode == DISTANCE):
                target_ip = int.from_bytes(data[12:16], byteorder='big')
                broadcast_dis = int.from_bytes(data[16:20], byteorder='big')
            else:
                assigned_ip = int.from_bytes(data[12:16], byteorder='big')
            ser_ip = source_ip

            if (mode == OFFER):
                self.send_greeting_send(ser_ip, assigned_ip, REQUEST, socket_send)
            elif (mode == ACKNOWLEDGE):
                self._serv_info[socket_send] = [des_ip, source_ip, 0, 0, 0]
                self.pkt = struct.pack('!LLLHH', des_ip, source_ip, LOCATION, self.location[0], self.location[1])
                socket_send.send(self.pkt)
            elif (mode == LOCATION):
                distance = pow(pow(self.location[0] - x, 2) + pow(self.location[1] - y, 2), 0.5)
                self._serv_info[socket_send] = [des_ip, source_ip, x, y, math.floor(distance)]
                for key, value in self._serv_info.items():
                    if key != socket_send:
                        # distance = pow(pow(value[2] - x, 2) + pow(value[3] - y, 2), 0.5)
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, source_ip, math.floor(distance) + value[4])
                        key.send(self.pkt)
            elif (mode == DISTANCE):
                for key, value in self._client_info.items():
                    if key != socket_send:
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, target_ip, value[4] + broadcast_dis)
                        key.send(self.pkt)
                for key, value in self._serv_info.items():
                    if key != socket_send:
                        # distance = pow(pow(value[2] - x, 2) + pow(value[3] - y, 2), 0.5)
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, target_ip, value[4] + broadcast_dis)
                        key.send(self.pkt)

    def send_greeting_send(self, ser_ip, assign_ip, mode, socket_send):
        self.pkt = self.create_greeting_send_pkt(ser_ip, assign_ip, mode)
        socket_send.send(self.pkt)

    @staticmethod
    def create_greeting_send_pkt(ser_ip, assign_ip, mode):
        if (mode == DISCOVERY):
            return struct.pack('!LLLL', 0, ser_ip, mode, assign_ip)
        elif (mode == REQUEST):
            return struct.pack('!LLLL', 0, ser_ip, mode, assign_ip)

class GlobalSwitch:
    def __init__(self, global_ip, location, len_ip=None, output=sys.stdout, debug_level=1):
        self.global_ip = global_ip
        self.my_ip = global_ip.split('/')[0] #string
        self.my_cidr = global_ip.split('/')[1]
        if (len_ip != None):
            self.len_ip = len_ip
            self.my_udp_ip = len_ip.split('/')[0]
            self.my_udp_cidr = len_ip.split('/')[1]
        else:
            self.len_ip = None
        self.location = location
        self._connect_info = (LOCAL_HOST, 0)
        self._serv_info = {}  # ser port: (ser IP, distance)
        self._client_info = {}  # assigned IP: socket
        self._socket = None
        self._socket_send = None
        self.pkt = b''
        self._output = output
        self._debug_level = debug_level
        self._start_time = time.time()

    def connected(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.bind((LOCAL_HOST, 0))
            self._socket.listen(254)
            return True
        except socket.error as err:
            print("Error encountered when opening socket:\n", err)
            return False

    def create_connection(self):
        print(self._socket.getsockname()[1])
        sys.stdout.flush()
        t = threading.Thread(target=self.greeting_recv)
        t.start()

    def greeting_recv(self):
        while True:
            if self.pkt:
                try:
                    data = socket_tcp.recv(RECV_SIZE)
                except socket.timeout:
                    # self.resend_packet(addrs)
                    continue
            else:
                socket_tcp, addrs = self._socket.accept()
                data = socket_tcp.recv(RECV_SIZE)

            source_ip = int.from_bytes(data[:4], byteorder='big')
            des_ip = int.from_bytes(data[4:8], byteorder='big')
            reserved = int.from_bytes(data[8:11], byteorder='big')
            mode = int.from_bytes(data[11:12], byteorder='big')
            if (mode == LOCATION):
                x = int.from_bytes(data[12:14], byteorder='big')
                y = int.from_bytes(data[14:16], byteorder='big')
            elif (mode == DISTANCE):
                target_ip = int.from_bytes(data[12:16], byteorder='big')
                broadcast_dis = int.from_bytes(data[16:20], byteorder='big')
            elif (mode == DATA):
                message = data[12:]
            elif (mode == QUERY):
                self.pkt = struct.pack('!LLL', des_ip, source_ip, AVAILABLE)
                socket_tcp.send(self.pkt)
            else:
                assigned_ip = int.from_bytes(data[12:16], byteorder='big')


            if (mode == DISCOVERY):
                give_ip = self.my_ip[:-1] + str(len(self._client_info) + 2)
                self.send_greeting(socket_tcp, give_ip, OFFER)
            elif (mode == REQUEST):
                self.send_greeting(socket_tcp, assigned_ip, ACKNOWLEDGE)
            elif (mode == LOCATION):
                distance_me_client = pow(pow(self.location[0] - x, 2) + pow(self.location[1] - y, 2), 0.5)
                self._client_info[socket_tcp] = [des_ip, source_ip, x, y, math.floor(distance_me_client)]
                self.pkt = struct.pack('!LLLHH', des_ip, source_ip, LOCATION, self.location[0], self.location[1])
                socket_tcp.send(self.pkt)
                for key, value in self._client_info.items():
                    if key != socket_tcp:
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, source_ip, value[4] + math.floor(distance_me_client))
                        key.send(self.pkt)
                for key, value in self._serv_info.items():
                    if key != socket_tcp:
                        # distance = pow(pow(value[2] - x, 2) + pow(value[3] - y, 2), 0.5)
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, source_ip, math.floor(distance_me_client) + value[4])
                        key.send(self.pkt)
                if self.len_ip is not None:
                    dis2 = pow(pow(self.location[0] - x, 2) + pow(self.location[1] - y, 2), 0.5)
                    self.pkt = struct.pack('!LLLLL', des_ip, source_ip, DISTANCE, ip_to_int(self.my_udp_ip), math.floor(dis2))
                    socket_tcp.send(self.pkt)
            elif (mode == DISTANCE):
                for key, value in self._client_info.items():
                    if key != socket_tcp:
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, target_ip, value[4] + broadcast_dis)
                        key.send(self.pkt)
                for key, value in self._serv_info.items():
                    if key != socket_tcp:
                        # distance = pow(pow(value[2] - x, 2) + pow(value[3] - y, 2), 0.5)
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, target_ip, value[4] + broadcast_dis)
                        key.send(self.pkt)
            elif (mode == DATA):
                for key, value in self._client_info.items():
                    if key != socket_tcp:

                        self.pkt = struct.pack('!LLL', ip_to_int(self.my_ip), des_ip, QUERY)
                        key.send(self.pkt)
                        # key.recvfrom(RECV_SIZE)
                        self.pkt = struct.pack('!LLL', source_ip, des_ip, DATA) + message
                        key.send(self.pkt)

                for key, value in self._serv_info.items():
                    self.pkt = struct.pack('!LLL', value[0], value[1], QUERY)
                    key.send(self.pkt)
                    # key.recvfrom(RECV_SIZE)
                    self.pkt = struct.pack('!LLL', source_ip, des_ip, DATA) + message
                    key.send(self.pkt)




    def send_greeting(self, socket_tcp, assign_ip, mode):
        self.pkt = self.create_greeting_pkt(self.my_ip, assign_ip, mode)
        socket_tcp.send(self.pkt)

    @staticmethod
    def create_greeting_pkt(source_ip, assign_ip, mode):
        if (mode == OFFER):
            return struct.pack('!LLLL', ip_to_int(source_ip), 0, mode, ip_to_int(assign_ip))
        elif (mode == ACKNOWLEDGE):
            return struct.pack('!LLLL', ip_to_int(source_ip), assign_ip, mode, assign_ip)

    def recv_input(self):
        while True:
            try:
                buffer = input("> ").split()
            except EOFError:
                break
            if ((len(buffer) != 2) or (buffer[0] != "connect")):
                continue
            port = int(buffer[1])
            t = threading.Thread(target=self.tcp_connect, args=(port,))
            t.start()

    def tcp_connect(self, port):
        socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_send.connect((LOCAL_HOST, port))
        self.send_greeting_send(0, 0, DISCOVERY, socket_send)
        while True:
            if self.pkt:
                try:
                    data = socket_send.recv(RECV_SIZE)
                except socket.timeout:
                    # self.resend_packet(addrs)
                    continue
            else:
                data = socket_send.recv(RECV_SIZE)

            source_ip = int.from_bytes(data[:4], byteorder='big')
            des_ip = int.from_bytes(data[4:8], byteorder='big')
            reserved = int.from_bytes(data[8:11], byteorder='big')
            mode = int.from_bytes(data[11:12], byteorder='big')
            if (mode == LOCATION):
                x = int.from_bytes(data[12:14], byteorder='big')
                y = int.from_bytes(data[14:16], byteorder='big')
            elif (mode == DISTANCE):
                target_ip = int.from_bytes(data[12:16], byteorder='big')
                broadcast_dis = int.from_bytes(data[16:20], byteorder='big')
            elif (mode == DATA):
                message = data[12:]
            elif (mode == QUERY):
                self.pkt = struct.pack('!LLL', des_ip, source_ip, AVAILABLE)
                socket_send.send(self.pkt)
            else:
                assigned_ip = int.from_bytes(data[12:16], byteorder='big')
            ser_ip = source_ip

            if (mode == OFFER):
                self.send_greeting_send(ser_ip, assigned_ip, REQUEST, socket_send)
            elif (mode == ACKNOWLEDGE):
                self._serv_info[socket_send] = [des_ip, source_ip, 0, 0, 0]
                self.pkt = struct.pack('!LLLHH', des_ip, source_ip, LOCATION, self.location[0], self.location[1])
                socket_send.send(self.pkt)
            elif (mode == LOCATION):
                distance = pow(pow(self.location[0] - x, 2) + pow(self.location[1] - y, 2), 0.5)
                self._serv_info[socket_send] = [des_ip, source_ip, x, y, math.floor(distance)]
                for key, value in self._client_info.items():
                    self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, source_ip, math.floor(distance) + value[4])
                    key.send(self.pkt)
                for key, value in self._serv_info.items():
                    if key != socket_send:
                        # distance = pow(pow(value[2] - x, 2) + pow(value[3] - y, 2), 0.5)
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, source_ip, math.floor(distance) + value[4])
                        key.send(self.pkt)
            elif (mode == DISTANCE):
                for key, value in self._client_info.items():
                    if key != socket_send:
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, target_ip, value[4] + broadcast_dis)
                        key.send(self.pkt)

                for key, value in self._serv_info.items():
                    if key != socket_send:
                        # distance = pow(pow(value[2] - x, 2) + pow(value[3] - y, 2), 0.5)
                        self.pkt = struct.pack('!LLLLL', value[0], value[1], DISTANCE, target_ip, value[4] + broadcast_dis)
                        key.send(self.pkt)

                # distance = calculate_distance(x, y, self.location[0], self.location[1])
                # for key, value in self._client_info.items():
                #     self.pkt = struct.pack('!LLLLL', key[0], key[1], DISTANCE, source_ip, distance)
                #     value.send(self.pkt)
            elif (mode == DATA):
                for key, value in self._client_info.items():
                    self.pkt = struct.pack('!LLL', value[0], value[1], QUERY)
                    key.send(self.pkt)
                    # key.recvfrom(RECV_SIZE)
                    self.pkt = struct.pack('!LLL', source_ip, des_ip, DATA) + message
                    key.send(self.pkt)

                for key, value in self._serv_info.items():
                    if key != socket_send:
                        self.pkt = struct.pack('!LLL', value[0], value[1], QUERY)
                        key.send(self.pkt)
                        # key.recvfrom(RECV_SIZE)
                        self.pkt = struct.pack('!LLL', source_ip, des_ip, DATA) + message
                        key.send(self.pkt)

    def send_greeting_send(self, ser_ip, assign_ip, mode, socket_send):
        self.pkt = self.create_greeting_send_pkt(ser_ip, assign_ip, mode)
        socket_send.send(self.pkt)

    @staticmethod
    def create_greeting_send_pkt(ser_ip, assign_ip, mode):
        if (mode == DISCOVERY):
            return struct.pack('!LLLL', 0, ser_ip, mode, assign_ip)
        elif (mode == REQUEST):
            return struct.pack('!LLLL', 0, ser_ip, mode, assign_ip)


def local_switch(argv):
    len_ip = argv[2]
    location = (int(argv[3]), int(argv[4]))
    udp_switch = LocalSwitch(len_ip, location)
    udp_switch.connected()
    udp_switch.create_connection()
    t = threading.Thread(target=udp_switch.recv_input)
    t.start()


def global_switch_recv(argv):
    global_ip = argv[2]
    location = (int(argv[3]), int(argv[4]))
    tcp_switch = GlobalSwitch(global_ip, location)
    tcp_switch.connected()
    tcp_switch.create_connection()
    t = threading.Thread(target=tcp_switch.recv_input)
    t.start()


def udp_tcp_switch(argv):
    len_ip = argv[2]
    global_ip = argv[3]
    location = (int(argv[4]), int(argv[5]))
    udp_switch = LocalSwitch(len_ip, location)
    udp_switch.connected()
    t = threading.Thread(target=udp_switch.create_connection)
    t.start()
    tcp_switch = GlobalSwitch(global_ip, location, len_ip)
    tcp_switch.connected()
    a = threading.Thread(target=tcp_switch.create_connection)
    a.start()


def main(argv):

    if (len(argv) == 5):
        if (argv[1] == "local"):
            local_switch(argv)
        elif (argv[1] == "global"):
            global_switch_recv(argv)
    elif(len(argv) == 6):
        if (argv[1] == "local"):
            udp_tcp_switch(argv)
    else:
        return


if __name__ == "__main__":
    main(sys.argv)
