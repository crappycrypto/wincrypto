from collections import namedtuple
import struct

from Crypto.Cipher import PKCS1_v1_5, ARC4, AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse


PUBLICKEYSTRUC = namedtuple('PUBLICKEYSTRUC', 'bType bVersion aiKeyAlg')  # reserved is skipped when unpacking
PUBLICKEYSTRUC_s = struct.Struct('<bb2xI')

PRIVATEKEYBLOB = namedtuple('PRIVATEKEYBLOB', 'modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent')

RSAPUBKEY = namedtuple('RSAPUBKEY', 'magic bitlen pubexp')
RSAPUBKEY_s = struct.Struct('<4sII')

RSAPUBKEY_MAGIC = 'RSA1'
PRIVATEKEYBLOB_MAGIC = 'RSA2'

# bType
bType_SIMPLEBLOB = 1
bType_PUBLICKEYBLOB = 6
bType_PRIVATEKEYBLOB = 7
bType_PLAINTEXTKEYBLOB = 8

# CALG
CALG_AES_128 = 0x660e
CALG_RC4 = 0x6801
CALG_RSA_KEYX = 0xa400

CUR_BLOB_VERSION = 2


def rsa_to_publickeystruc(rsa_key):
    n = rsa_key.key.n
    e = rsa_key.key.e
    n_bytes = long_to_bytes(n)[::-1]
    result = PUBLICKEYSTRUC_s.pack(bType_PUBLICKEYBLOB, CUR_BLOB_VERSION, CALG_RSA_KEYX)
    result += RSAPUBKEY_s.pack(RSAPUBKEY_MAGIC, len(n_bytes) * 8, e)
    result += n_bytes
    return result


def rsa_to_privatekeystruc(rsa_key):
    n = rsa_key.key.n
    e = rsa_key.key.e
    d = rsa_key.key.d
    p = rsa_key.key.p
    q = rsa_key.key.q

    n_bytes = long_to_bytes(n)[::-1]
    key_len = len(n_bytes) * 8
    result = PUBLICKEYSTRUC_s.pack(bType_PRIVATEKEYBLOB, CUR_BLOB_VERSION, CALG_RSA_KEYX)
    result += RSAPUBKEY_s.pack(PRIVATEKEYBLOB_MAGIC, key_len, e)
    result += n_bytes
    result += long_to_bytes(p, key_len / 16)[::-1]
    result += long_to_bytes(q, key_len / 16)[::-1]
    result += long_to_bytes(d % (p - 1), key_len / 16)[::-1]
    result += long_to_bytes(d % (q - 1), key_len / 16)[::-1]
    result += long_to_bytes(inverse(q, p), key_len / 16)[::-1]
    result += long_to_bytes(d, key_len / 8)[::-1]
    return result


def aes128_to_plaintextkeyblob(aes_key):
    result = PUBLICKEYSTRUC_s.pack(bType_PLAINTEXTKEYBLOB, 2, CALG_AES_128)
    result += struct.pack('<I', len(aes_key))
    result += aes_key
    return result


def rc4_to_plaintextkeyblob(rc4_key):
    result = PUBLICKEYSTRUC_s.pack(bType_PLAINTEXTKEYBLOB, 2, CALG_RC4)
    result += struct.pack('<I', len(rc4_key))
    result += rc4_key
    return result


def rc4_to_simpleblob(rc4_key, rsa_key):
    result = PUBLICKEYSTRUC_s.pack(bType_SIMPLEBLOB, CUR_BLOB_VERSION, CALG_RC4)
    result += struct.pack('<I', CALG_RSA_KEYX)
    c = PKCS1_v1_5.new(rsa_key)
    encrypted_key = c.encrypt(rc4_key)
    result += encrypted_key[::-1]
    return result


def aes128_to_simpleblob(aes_key, rsa_key):
    result = PUBLICKEYSTRUC_s.pack(bType_SIMPLEBLOB, CUR_BLOB_VERSION, CALG_AES_128)
    result += struct.pack('<I', CALG_RSA_KEYX)
    c = PKCS1_v1_5.new(rsa_key)
    encrypted_key = c.encrypt(aes_key)
    result += encrypted_key[::-1]
    return result


def import_publickeystruc(data, priv_key=None):
    publickeystruc = PUBLICKEYSTRUC._make(PUBLICKEYSTRUC_s.unpack_from(data))
    if publickeystruc.bType == bType_PUBLICKEYBLOB and publickeystruc.bVersion == CUR_BLOB_VERSION and \
                    publickeystruc.aiKeyAlg == CALG_RSA_KEYX:
        rsapubkey = RSAPUBKEY._make(RSAPUBKEY_s.unpack_from(data[8:]))
        if rsapubkey.magic == RSAPUBKEY_MAGIC:
            bitlen8 = rsapubkey.bitlen / 8
            modulus = bytes_to_long(data[20:20 + bitlen8][::-1])
            r = RSA.construct((modulus, long(rsapubkey.pubexp)))
            return r

    if publickeystruc.bType == bType_PRIVATEKEYBLOB and publickeystruc.bVersion == CUR_BLOB_VERSION and \
                    publickeystruc.aiKeyAlg == CALG_RSA_KEYX:
        rsapubkey = RSAPUBKEY._make(RSAPUBKEY_s.unpack_from(data[8:]))
        if rsapubkey.magic == PRIVATEKEYBLOB_MAGIC:
            bitlen8 = rsapubkey.bitlen / 8
            bitlen16 = rsapubkey.bitlen / 16
            privatekeyblob_s = struct.Struct(
                '%ds%ds%ds%ds%ds%ds%ds' % (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8))
            privatekey = PRIVATEKEYBLOB._make(bytes_to_long(x[::-1]) for x in privatekeyblob_s.unpack_from(data[20:]))

            r = RSA.construct((privatekey.modulus, long(rsapubkey.pubexp), privatekey.privateExponent,
                               privatekey.prime1, privatekey.prime2))
            return r

    if publickeystruc.bType == bType_PLAINTEXTKEYBLOB and publickeystruc.bVersion == CUR_BLOB_VERSION and \
                    publickeystruc.aiKeyAlg == CALG_RC4:
        key_len = struct.unpack('<I', data[8:12])[0]
        key = data[12:12 + key_len]
        return key

    if publickeystruc.bType == bType_SIMPLEBLOB and publickeystruc.bVersion == CUR_BLOB_VERSION and \
                    publickeystruc.aiKeyAlg == CALG_RC4:
        assert struct.unpack('<I', data[8:12])[0] == CALG_RSA_KEYX
        assert priv_key
        pkcs_1_encrypted_key = data[12:][::-1]
        c = PKCS1_v1_5.new(priv_key)
        return c.decrypt(pkcs_1_encrypted_key, None)

    raise NotImplementedError('Microsoft key type not yet implemented')


def rsa_decrypt(rsa_key, data):
    data = data[::-1]
    c = PKCS1_v1_5.new(rsa_key)
    result = c.decrypt(data, None)
    return result


def rsa_encrypt(rsa_key, data):
    c = PKCS1_v1_5.new(rsa_key)
    result = c.encrypt(data)
    result = result[::-1]
    return result


def rc4_encrypt(rc4_key, data):
    return ARC4.new(rc4_key).encrypt(data)


def rc4_decrypt(rc4_key, data):
    return ARC4.new(rc4_key).decrypt(data)


def aes128_encrypt(aes_key, data):
    data = add_pkcs5_padding(data, 16)
    encrypted = AES.new(aes_key, mode=AES.MODE_CBC, IV='\0' * 16).encrypt(data)
    return encrypted


def aes128_decrypt(aes_key, data):
    decrypted = AES.new(aes_key, mode=AES.MODE_CBC, IV='\0' * 16).decrypt(data)
    return remove_pkcs5_padding(decrypted)


def remove_pkcs5_padding(data):
    padding_length = ord(data[-1])
    return data[:-padding_length]


def add_pkcs5_padding(data, blocksize):
    last_block_len = len(data) % blocksize
    padding_length = blocksize - last_block_len
    if padding_length == 0:
        padding_length = blocksize
    return data + chr(padding_length) * padding_length