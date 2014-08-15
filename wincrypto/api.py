from abc import abstractproperty, ABCMeta
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


def remove_pkcs5_padding(data):
    padding_length = ord(data[-1])
    return data[:-padding_length]


def add_pkcs5_padding(data, blocksize):
    last_block_len = len(data) % blocksize
    padding_length = blocksize - last_block_len
    if padding_length == 0:
        padding_length = blocksize
    return data + chr(padding_length) * padding_length


class crypt_key(object):
    def __init__(self, key):
        self.key = key


class RSA_keyx(crypt_key):
    @classmethod
    def import_publickeyblob(cls, data):
        rsapubkey = RSAPUBKEY._make(RSAPUBKEY_s.unpack_from(data))
        assert rsapubkey.magic == RSAPUBKEY_MAGIC
        bitlen8 = rsapubkey.bitlen / 8
        modulus = bytes_to_long(data[12:12 + bitlen8][::-1])
        r = RSA.construct((modulus, long(rsapubkey.pubexp)))
        return cls(r)

    def export_publickeyblob(self):
        n = self.key.key.n
        e = self.key.key.e
        n_bytes = long_to_bytes(n)[::-1]
        result = PUBLICKEYSTRUC_s.pack(bType_PUBLICKEYBLOB, CUR_BLOB_VERSION, CALG_RSA_KEYX)
        result += RSAPUBKEY_s.pack(RSAPUBKEY_MAGIC, len(n_bytes) * 8, e)
        result += n_bytes
        return result

    @classmethod
    def import_privatekeyblob(cls, data):
        rsapubkey = RSAPUBKEY._make(RSAPUBKEY_s.unpack_from(data))
        assert rsapubkey.magic == PRIVATEKEYBLOB_MAGIC
        bitlen8 = rsapubkey.bitlen / 8
        bitlen16 = rsapubkey.bitlen / 16
        privatekeyblob_s = struct.Struct(
            '%ds%ds%ds%ds%ds%ds%ds' % (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8))
        privatekey = PRIVATEKEYBLOB._make(bytes_to_long(x[::-1]) for x in privatekeyblob_s.unpack_from(data[12:]))

        r = RSA.construct((privatekey.modulus, long(rsapubkey.pubexp), privatekey.privateExponent,
                           privatekey.prime1, privatekey.prime2))
        return cls(r)

    def export_privatekeyblob(self):
        key = self.key.key
        n = key.n
        e = key.e
        d = key.d
        p = key.p
        q = key.q

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

    def decrypt(self, data):
        data = data[::-1]
        c = PKCS1_v1_5.new(self.key)
        result = c.decrypt(data, None)
        return result


    def encrypt(self, data):
        c = PKCS1_v1_5.new(self.key)
        result = c.encrypt(data)
        result = result[::-1]
        return result


class symmetric_crypt_key(crypt_key):
    __metaclass__ = ABCMeta
    alg_id = abstractproperty()

    @classmethod
    def import_plaintextkeyblob(cls, data):
        key_len = struct.unpack('<I', data[:4])[0]
        key = data[4:4 + key_len]
        return cls(key)

    def export_plaintextkeyblob(self):
        result = PUBLICKEYSTRUC_s.pack(bType_PLAINTEXTKEYBLOB, 2, self.alg_id)
        result += struct.pack('<I', len(self.key))
        result += self.key
        return result

    @classmethod
    def import_simpleblob(cls, data, hPubKey):
        assert struct.unpack('<I', data[:4])[0] == CALG_RSA_KEYX
        assert hPubKey
        pkcs_1_encrypted_key = data[4:][::-1]
        c = PKCS1_v1_5.new(hPubKey)
        key = c.decrypt(pkcs_1_encrypted_key, None)
        return cls(key)

    def export_simpleblob(self, rsa_key):
        result = PUBLICKEYSTRUC_s.pack(bType_SIMPLEBLOB, CUR_BLOB_VERSION, self.alg_id)
        result += struct.pack('<I', CALG_RSA_KEYX)
        c = PKCS1_v1_5.new(rsa_key)
        encrypted_key = c.encrypt(self.key)
        result += encrypted_key[::-1]
        return result


class RC4_crypt_key(symmetric_crypt_key):
    alg_id = CALG_RC4

    def encrypt(self, data):
        return ARC4.new(self.key).encrypt(data)

    def decrypt(self, data):
        return ARC4.new(self.key).encrypt(data)


class AES128_crypt_key(symmetric_crypt_key):
    alg_id = CALG_AES_128


    def encrypt(self, data):
        data = add_pkcs5_padding(data, 16)
        encrypted = AES.new(self.key, mode=AES.MODE_CBC, IV='\0' * 16).encrypt(data)
        return encrypted

    def decrypt(self, data):
        decrypted = AES.new(self.key, mode=AES.MODE_CBC, IV='\0' * 16).decrypt(data)
        result = remove_pkcs5_padding(decrypted)
        return result


algorithm_registry = {
    CALG_RSA_KEYX: RSA_keyx,
    CALG_RC4: RC4_crypt_key,
    CALG_AES_128: AES128_crypt_key,
}


def CryptImportKey(data, pub_key=None):
    publickeystruc = PUBLICKEYSTRUC._make(PUBLICKEYSTRUC_s.unpack_from(data))
    if publickeystruc.bVersion != CUR_BLOB_VERSION:
        raise NotImplementedError('PUBLICKEYSTRUC.bVersion={} not implemented'.format(publickeystruc.bVersion))

    if publickeystruc.bType == bType_PUBLICKEYBLOB:
        if publickeystruc.aiKeyAlg not in algorithm_registry:
            raise NotImplementedError('ALG_ID {:x} not implemented'.format(publickeystruc.aiKeyAlg))
        return algorithm_registry[publickeystruc.aiKeyAlg].import_publickeyblob(data[8:])

    if publickeystruc.bType == bType_PRIVATEKEYBLOB:
        if publickeystruc.aiKeyAlg not in algorithm_registry:
            raise NotImplementedError('ALG_ID {:x} not implemented'.format(publickeystruc.aiKeyAlg))
        return algorithm_registry[publickeystruc.aiKeyAlg].import_privatekeyblob(data[8:])

    if publickeystruc.bType == bType_PLAINTEXTKEYBLOB:
        if publickeystruc.aiKeyAlg not in algorithm_registry:
            raise NotImplementedError('ALG_ID {:x} not implemented'.format(publickeystruc.aiKeyAlg))
        return algorithm_registry[publickeystruc.aiKeyAlg].import_plaintextkeyblob(data[8:])

    if publickeystruc.bType == bType_SIMPLEBLOB:
        if publickeystruc.aiKeyAlg not in algorithm_registry:
            raise NotImplementedError('ALG_ID {:x} not implemented'.format(publickeystruc.aiKeyAlg))
        return algorithm_registry[publickeystruc.aiKeyAlg].import_simpleblob(data[8:], pub_key)

    raise NotImplementedError('PUBLICKEYSTRUC.bType={} not implemented'.format(publickeystruc.bType))


def CryptDecrypt(crypt_key, encrypted_data):
    return crypt_key.decrypt(encrypted_data)


def CryptEncrypt(crypt_key, plain_data):
    return crypt_key.encrypt(plain_data)


def CryptExportKey(crypt_key, exp_key, blob_type):
    if blob_type == bType_SIMPLEBLOB:
        return crypt_key.export_simpleblob(exp_key)
    elif blob_type == bType_PLAINTEXTKEYBLOB:
        return crypt_key.export_plaintextkeyblob()
    elif blob_type == bType_PUBLICKEYBLOB:
        return crypt_key.export_publickeyblob()
    elif blob_type == bType_PRIVATEKEYBLOB:
        return crypt_key.export_privatekeyblob()
    else:
        raise NotImplementedError('blob_type={} not supported'.format(blob_type))