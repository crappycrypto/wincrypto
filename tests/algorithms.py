import unittest
from binascii import a2b_hex

import wincrypto
from wincrypto.algorithms import symmetric_algorithms, hash_algorithms
from wincrypto.api import CryptImportKey, CryptExportKey, CryptCreateHash, CryptDeriveKey, \
    CryptHashData
from wincrypto.constants import bType_PLAINTEXTKEYBLOB, CALG_MD5, CALG_RC4, CALG_SHA1, CALG_AES_192, bType_SIMPLEBLOB


TEST_RSA_PRIVATE_PEM = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCaAuiiYlR++UcrvGWdBXLJc2DIFtOXHK8ZSwLf8U279sLuh4Cz
LY9iT0i9ABqakJ3rPw/zV4ZizvWhkZuyx9/uWM7a27NLizObr8oi+CEGIPgnFCqE
//+Nk82mR5EPeCZ6ofZwuPsC/JUlcC+BtUfT7a3oWMnOk3CjFwYAdXVT0QIDAQAB
AoGAQjCZ1qA3/FIaGlvft/pNePLTV2soCLvVLSOl2qUUaYIGCQnHcDpWc0Pr2P6g
cGlS1XXG3yhwoyqbOpMfvVhVjqjOUvH71BZJbxyXoXeuvk6GOKivadqCfdAqGX8V
zAzXVw2vk8D9BzQYS1DWirynSjL76H/d24A99YHvUPG/hzkCQQC1SraaeZufxcJK
1D+9iRr0aDGgOoZL4fWge8MTortM2YbdUAFbzBVXdfl7Sm9Y9mKLacaPERKbrAFh
ikhjdFybAkEA2XpBTON38t5EXxBon/hMV4MT+8x9DyXJ87h3/yq0ojnrvgu6RSnD
ltalpc3KJZ7WO4vP8/IcDjkG/1UxJNmaAwJBAK5oz12zioVeEro8kYm9QkJJjxyP
0S1lmBGpnxXf44NebkGxu2zd3NZEeBwlkxOqDUoEG/L9QMKk6rs09sk/Y+sCQGAD
r6zIiH57TuhBkE+ACgRg5IO4pkX3ww+NE71eF13AAKpo9xXt+GIx5fQrxOGTHLYx
ZeAntec5mjNEY2wHfg0CQQCURZoU82O4RDNofV2iMoQYjMOMBTusHXE+RBb0WLhu
opeJSYOOCFE/fRWapqXo1TIEDlCkYYlufIa6FkFc/wAL
-----END RSA PRIVATE KEY-----'''

TEST_RSA_PUBLIC_PEM = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaAuiiYlR++UcrvGWdBXLJc2DI
FtOXHK8ZSwLf8U279sLuh4CzLY9iT0i9ABqakJ3rPw/zV4ZizvWhkZuyx9/uWM7a
27NLizObr8oi+CEGIPgnFCqE//+Nk82mR5EPeCZ6ofZwuPsC/JUlcC+BtUfT7a3o
WMnOk3CjFwYAdXVT0QIDAQAB
-----END PUBLIC KEY-----'''

TEST_DATA = bytes(bytearray(range(64)))  # 64 is a multiple of most blocksizes


class TestSymmetricKey(unittest.TestCase):
    def test_export_import_plain(self):
        for algorithm in symmetric_algorithms:
            instance = algorithm(b'A' * algorithm.key_len)
            blob = CryptExportKey(instance, None, bType_PLAINTEXTKEYBLOB)
            instance2 = CryptImportKey(blob)
            self.assertEqual(instance.key, instance2.key)

    def test_export_import_simple(self):
        rsa_key = wincrypto.algorithms.RSA_KEYX.from_pem(TEST_RSA_PRIVATE_PEM)
        for algorithm in symmetric_algorithms:
            instance = algorithm(b'A' * algorithm.key_len)
            blob = CryptExportKey(instance, rsa_key, bType_SIMPLEBLOB)
            instance2 = CryptImportKey(blob, rsa_key)
            self.assertEqual(instance.key, instance2.key)

    def test_encrypt_decrypt(self):
        for algorithm in symmetric_algorithms:
            instance = algorithm(b'A' * algorithm.key_len)
            c = instance.encrypt(TEST_DATA)
            p = instance.decrypt(c)
            self.assertEqual(TEST_DATA, p)


class TestRsa(unittest.TestCase):
    def test_rsa_public_import_export(self):
        rsa_key = wincrypto.algorithms.RSA_KEYX.from_pem(TEST_RSA_PUBLIC_PEM)
        ms_key = rsa_key.export_publickeyblob()
        aes_key2 = wincrypto.CryptImportKey(ms_key)
        self.assertEqual(rsa_key.key, aes_key2.key)

    def test_rsa_private_import_export(self):
        rsa_key = wincrypto.algorithms.RSA_KEYX.from_pem(TEST_RSA_PRIVATE_PEM)
        ms_key = rsa_key.export_privatekeyblob()
        aes_key2 = wincrypto.CryptImportKey(ms_key)
        self.assertEqual(rsa_key.key, aes_key2.key)

    def test_rsa_encrypt_decrypt(self):
        private_key = wincrypto.algorithms.RSA_KEYX.from_pem(TEST_RSA_PRIVATE_PEM)
        public_key = wincrypto.algorithms.RSA_KEYX.from_pem(TEST_RSA_PUBLIC_PEM)
        c = public_key.encrypt(TEST_DATA)
        p = private_key.decrypt(c)
        self.assertEqual(TEST_DATA, p)


class TestHash(unittest.TestCase):
    def test_hash_len(self):
        for algorithm in hash_algorithms:
            instance = algorithm()
            hash_val = instance.get_hash_val()
            hash_size = instance.get_hash_size()
            self.assertEqual(len(hash_val), hash_size)

class TestCryptDeriveKey(unittest.TestCase):
    def test_cryptderivekey_md5_rc4(self):
        md5_hash = CryptCreateHash(CALG_MD5)
        CryptHashData(md5_hash, b'Test')
        rc4_key = CryptDeriveKey(md5_hash, CALG_RC4)
        known_key = a2b_hex('0cbc6611f5540bd0809a388dc95a615b')
        self.assertEqual(rc4_key.key, known_key)

    def test_cryptderivekey_sha1_aes192(self):
        sha1_hash = CryptCreateHash(CALG_SHA1)
        CryptHashData(sha1_hash, b'Test')
        aes_key = CryptDeriveKey(sha1_hash, CALG_AES_192)
        known_key = a2b_hex(b'97d4f8389786352382ce6079c28d6ed3d65021a99b96263e')
        print(1)
        self.assertEqual(aes_key.key, known_key)