import sys

# python2/3 compatibility
if sys.version > '3':
    byte2int = lambda x: x
else:
    byte2int = ord


def remove_pkcs5_padding(data):
    padding_length = byte2int(data[-1])
    return data[:-padding_length]


def add_pkcs5_padding(data, blocksize):
    last_block_len = len(data) % blocksize
    padding_length = blocksize - last_block_len
    if padding_length == 0:
        padding_length = blocksize
    return data + bytes(bytearray([padding_length] * padding_length))


# algorithm taken from msdn documentation for CryptDeriveKey
def derive_key_3des_aes(hash_alg):
    from wincrypto.api import CryptCreateHash

    buf1 = bytearray(b'\x36' * 64)
    hash_val = bytearray(hash_alg.get_hash_val())
    for x in range(len(hash_val)):
        buf1[x] ^= hash_val[x]
    buf2 = bytearray(b'\x5c' * 64)
    for x in range(len(hash_val)):
        buf2[x] ^= hash_val[x]
    hash1 = CryptCreateHash(hash_alg.alg_id)
    hash1.hash_data(bytes(buf1))
    hash2 = CryptCreateHash(hash_alg.alg_id)
    hash2.hash_data(bytes(buf2))
    derived_key = hash1.get_hash_val() + hash2.get_hash_val()
    return derived_key


def GET_ALG_CLASS(x):
    return x & (7 << 13)
