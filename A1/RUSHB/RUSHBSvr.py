import socket
import sys


RUSHB_PACKET_SIZE = 1500
PAYLOAD_SIZE = 1464
ENC_KEY = 11
DEC_KEY = 15
MOD = 249

DAT = '0001000'
FIN = '0000100'
ACG_FIN = '1000100'
FIN_ENC = '0000101'
CHECK_SUM_FLAG = '0'
ENCRYPT_FLAG = '0'


def str_to_int(string, pad=PAYLOAD_SIZE):
    b_str = string.encode("UTF-8")
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return int.from_bytes(b_str, byteorder='big')


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff


def encode(payload, key=ENC_KEY, n=MOD):
    result = b""
    for c in payload:
        result += ((c ** key) % n).to_bytes(1, 'big')
    return result


def decode(payload, key=DEC_KEY, n=MOD):
    result = b""
    for c in payload:
        result += ((c ** key) % n).to_bytes(1, 'big')
    return result


def change_flags(flags, index, char = '1'):
    flags = list(flags)
    flags[index] = char
    flags = ''.join(flags)
    return flags


def check_reversed_num(reversed):
    for c in reversed:
        if c != '0':
            return 0
    return 1


class Server:
    def __init__(self):
        # create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # choose local host
        self.socket.bind(('127.0.0.1', 0))
        self.file_content = ''
        self.pkt = b''
        self.sequence = 0
        self.c_sequence = 0

    def run(self):
        global CHECK_SUM_FLAG
        global ENCRYPT_FLAG
        # print a valid port
        print(self.socket.getsockname()[1])
        sys.stdout.flush()

        while True:
            if self.pkt:
                try:
                    # receive UDP data and address
                    data, addrs = self.socket.recvfrom(RUSHB_PACKET_SIZE)
                except socket.timeout:
                    self.resend_packet(addrs)
                    continue
            else:
                data, addrs = self.socket.recvfrom(RUSHB_PACKET_SIZE)

            seq_num = int.from_bytes(data[:2], byteorder='big')
            ack_num = int.from_bytes(data[2:4], byteorder='big')
            check_sum = int.from_bytes(data[4:6], byteorder='big')

            forth_line = bin(int.from_bytes(data[6: 8], byteorder='big'))[2:].zfill(16)
            flags = forth_line[:7]
            reserved = forth_line[7:13]
            version = forth_line[13:]

            # if all([c == '0' for c in reserved]):
            if check_reversed_num(reserved):

                if ENCRYPT_FLAG == '1':
                    if flags[6] != '1':
                        continue

                if CHECK_SUM_FLAG == '1':
                    if check_sum != compute_checksum(data[8:]) or flags[5] != '1':
                        continue

                if flags[2] == '1' and flags[4] == '0':         # GET
                    if flags[5] == '1':
                        CHECK_SUM_FLAG = '1'
                    if seq_num == 1 and ack_num == 0:
                        file_name = self.get_file_name(data[8:])
                        if file_name:  # file_content name exist
                            try:
                                open(file_name, 'r')
                            except (FileNotFoundError, UnicodeDecodeError):
                                ENCRYPT_FLAG = '1'

                            if ENCRYPT_FLAG == '1':
                                file_name = decode(file_name)

                            try:
                                self.file_content = self.read_file(file_name)
                            except (FileNotFoundError, UnicodeDecodeError):
                                self.file_content = ''
                                self.sequence += 1
                                self.pkt = self.create_pkt(self.sequence, 0, check_sum, FIN_ENC)
                                self.socket.sendto(self.pkt, addrs)
                                self.c_sequence = seq_num
                                continue

                            if CHECK_SUM_FLAG == '1':
                                if check_sum != compute_checksum(data[8:]):
                                    continue
                            self.send_packet(addrs, seq_num, check_sum)
                elif flags[0] == '1' and flags[3] == '1':    # ACK_DAT
                    #检查seqNum和ackNum，并且filename（payload）有东西
                    if self.check_seq_ack_num(seq_num, ack_num) and self.get_file_name(data[8:]).rstrip(b'\x00') is not None:
                        if len(self.file_content) > 0:      # file_content sending is working
                            self.send_packet(addrs, seq_num, check_sum)
                        else:                       # file_content sending has finished (send FIN)
                            self.sequence += 1
                            self.pkt = self.create_pkt(self.sequence, 0, check_sum, FIN)
                            self.socket.sendto(self.pkt, addrs)
                            self.c_sequence = seq_num
                elif flags[1] == '1' and flags[3] == '1':    # NAK_DAT
                    if self.check_seq_ack_num(seq_num, ack_num) and self.get_file_name(data[8:]).rstrip(b'\x00') is not None:
                        if self.pkt:
                            self.resend_packet(addrs)
                            self.c_sequence = seq_num
                elif flags[0] == '1' and flags[4] == '1':     # ACK_FIN
                    if self.check_seq_ack_num(seq_num, ack_num) and self.get_file_name(data[8:]).rstrip(b'\x00') is not None:
                        self.sequence += 1
                        self.pkt = self.create_pkt(self.sequence, seq_num, check_sum, ACG_FIN)
                        self.socket.sendto(self.pkt, addrs)
                        self.socket.close()
                        sys.exit()

    def send_packet(self, addrs, seq_num, check_sum):
        self.socket.settimeout(None)
        self.sequence += 1
        #把pkt中从头到payload长度的内容发过去

        self.pkt = self.create_pkt(self.sequence, 0, check_sum, DAT, self.file_content[:PAYLOAD_SIZE])
        # 把file中上行代码发送过的内容删除
        self.file_content = self.file_content[PAYLOAD_SIZE:]
        self.socket.sendto(self.pkt, addrs)
        self.c_sequence = seq_num
        self.socket.settimeout(4)

    def resend_packet(self, addrs):
        self.socket.sendto(self.pkt, addrs)
        self.socket.settimeout(4)

    def check_seq_ack_num(self, sequence, ack):
        if sequence == self.c_sequence + 1 and ack == self.sequence:
            return True
        return False

    @staticmethod
    def read_file(file_name):
        fp = open(file_name, 'r')
        file_content = fp.read()
        fp.close()
        return file_content

    @staticmethod
    def get_file_name(payload):
        # 删除paylod最后的0
        return payload.rstrip(b'\x00')

    @staticmethod
    def create_pkt(seq_num, ack_num, check_sum, flags, file_content=None):
        global CHECK_SUM_FLAG

        if file_content is None:
            payload = (0).to_bytes(PAYLOAD_SIZE, byteorder='big')
        else:
            payload = str_to_int(file_content).to_bytes(PAYLOAD_SIZE, byteorder='big')

        header = ''
        header += bin(seq_num)[2:].zfill(16)
        header += bin(ack_num)[2:].zfill(16)
        flags = list(flags)
        if CHECK_SUM_FLAG == '1':
            if ENCRYPT_FLAG == '1':
                payload = encode(payload)
                flags[6] = '1'
            check_sum = bin(compute_checksum(payload))[2:].zfill(16)
            header += check_sum
            flags[5] = '1'
        else:
            if ENCRYPT_FLAG == '1':
                payload = encode(payload)
                flags[6] = '1'

            header += bin(check_sum)[2:].zfill(16)
        flags = ''.join(flags)
        header += flags.ljust(16, '0')
        # 把header中二进制转成十进制然后加上payload转成byte
        return bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)]) + payload


if __name__ == '__main__':
    Server().run()



