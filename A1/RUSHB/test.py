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

ENC_KEY = 11
DEC_KEY = 15
MOD = 249
DAT_ACK = '1001000'

def change_flags(flags, index):
    flags = list(flags)
    flags[index] = '1'
    flags = ''.join(flags)
    return flags

def encode(payload, key=DEC_KEY, n=MOD):
    result = b""
    for c in payload:
        result += ((c ** key) % n).to_bytes(1, 'big')
    return result

f = open(b'')
DAT = change_flags(DAT_ACK, 5)
print(DAT)

# Data = b"i\xbax\x8c\x85\x80i\xbax\x8c\xe8V\xb7V"
# str = b"i\xbax\x8c\x85\x80i\xbax\x8c\xe8V\xb7V"
#
# print(encode(str))

# print(bin(compute_checksum(bytestr))[2:].zfill(16))