import math
import socket
import struct
import sys
import traceback
import os.path
import time
import threading

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


class Connection:
    def __init__(self, serv_port, output=sys.stdout, debug_level=1):
        self._my_ip = 0
        self._connect_info = (LOCAL_HOST, 0)
        self._serv_info = (0, serv_port) # server IP, server port
        self._socket = None
        self.pkt = b''
        self._des_ip = 0
        self._output = output
        self._debug_level = debug_level
        self._start_time = time.time()

    def connect(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind(self._connect_info)
            return True
        except socket.error as err:
            print("Error encountered when opening socket:\n", err)
            return False

    def greeting(self):
        global FLAG
        self.send_greeting(DISCOVERY)
        FLAG += 1
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
            assigned_ip = int.from_bytes(data[12:16], byteorder='big')

            self._serv_info = (source_ip, self._serv_info[1])
            if (mode == OFFER and FLAG == 1):
                self._my_ip = assigned_ip
                self.send_greeting(REQUEST)
                FLAG += 1
            elif (mode == ACKNOWLEDGE and FLAG == 2):
                self._my_ip = des_ip
                FLAG += 1
                break

    def sending(self):
        global FLAG
        while True:
            if (FLAG < 3):
                continue
            try:
                buffer = input("> ").split()
            except EOFError:
                break

            self._des_ip = ip_to_int(buffer[1])
            data = buffer[2].strip('"')
            self.send_sending(DATA, data)

    def receiving(self):
        global FLAG
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
            self._serv_info = (source_ip, self._serv_info[1])
            self._des_ip = source_ip
            if (mode == QUERY and FLAG == 3):
                self.send_receiving(AVAILABLE)
                FLAG += 1
            elif (mode == DATA and FLAG == 4):
                payload = int.from_bytes(data[12:], byteorder='big')
                sys.stdout.write("\x08\x08Received from " + int_to_ip(source_ip) + ": " + int_to_str(payload, len(data[12:])) + "\n>")
                sys.stdout.flush()
                FLAG -= 1
                # break
            elif (mode == MORE_FRAG and FLAG == 4):
                payload = int_to_str(int.from_bytes(data[12:], byteorder='big'), len(data[12:]))
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
                    self._serv_info = (source_ip, self._serv_info[1])
                    self._des_ip = source_ip

                    if (mode == MORE_FRAG and FLAG == 4):
                        payload += int_to_str(int.from_bytes(data[12:], byteorder='big'), len(data[12:]))
                    elif (mode == END_FRAG and FLAG == 4):
                        payload += int_to_str(int.from_bytes(data[12:], byteorder='big'), len(data[12:]))
                        FLAG -= 1
                        break
                sys.stdout.write("\x08\x08Received from " + int_to_ip(source_ip) + ": " + payload + "\n>")
                sys.stdout.flush()
                # break

    def close(self):
        self._socket.close()

    def send_receiving(self, mode):
        self.pkt = self.create_receiving_pkt(self._my_ip, self._des_ip, mode)
        self._socket.sendto(self.pkt, (LOCAL_HOST, self._serv_info[1]))

    def send_sending(self, mode, data):
        self.pkt = self.create_sending_pkt(self._my_ip, self._des_ip, mode, data)
        self._socket.sendto(self.pkt, (LOCAL_HOST, self._serv_info[1]))

    def send_greeting(self, mode):
        self.pkt = self.create_greeting_pkt(self._serv_info, self._my_ip, mode)
        self._socket.sendto(self.pkt, (LOCAL_HOST, self._serv_info[1]))

    @staticmethod
    def create_receiving_pkt(my_ip, des_ip, mode):
        if (mode == AVAILABLE):
            return struct.pack('!LLL', my_ip, des_ip, mode)

    @staticmethod
    def create_sending_pkt(my_ip, des_ip, mode, data):
        data = str_to_int(data).to_bytes(len(data), byteorder='big')
        if (mode == DATA):
            return struct.pack('!LLL', my_ip, des_ip, mode) + data

    @staticmethod
    def create_greeting_pkt(serv_info, assign_ip, mode):
        if (mode == DISCOVERY):
            return struct.pack('!LLLL', 0, serv_info[0], mode, assign_ip)
        elif (mode == REQUEST):
            return struct.pack('!LLLL', 0, serv_info[0], mode, assign_ip)


def main(argv):
    if (len(argv) != 2):
        return
    serv_port = int(argv[1])
    debug_level = 2
    output = sys.stdout

    conn = Connection(serv_port, output, debug_level)
    conn.connect()
    # if not conn.connect():
    #     return
    conn.greeting()
    a = threading.Thread(target=conn.sending)
    t = threading.Thread(target=conn.receiving)
    a.start()
    t.start()
    a.join()
    t.join()
    conn.close()


# python3 RUSHBAdapter.py 60829
if __name__ == "__main__":
    main(sys.argv)

