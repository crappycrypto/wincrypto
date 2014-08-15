import platform
import unittest

from Crypto.PublicKey import RSA

import wincrypto
from wincrypto import native
import wincrypto.api


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

TEST_RSA_PUBLIC_MSKEYBLOB = '\x06\x02\x00\x00\x00\xa4\x00\x00RSA1\x00\x04\x00\x00\x01\x00\x01\x00\xd1Suu\x00\x06\x17\xa3p\x93\xce\xc9X\xe8\xad\xed\xd3G\xb5\x81/p%\x95\xfc\x02\xfb\xb8p\xf6\xa1z&x\x0f\x91G\xa6\xcd\x93\x8d\xff\xff\x84*\x14\'\xf8 \x06!\xf8"\xca\xaf\x9b3\x8bK\xb3\xdb\xda\xceX\xee\xdf\xc7\xb2\x9b\x91\xa1\xf5\xceb\x86W\xf3\x0f?\xeb\x9d\x90\x9a\x1a\x00\xbdHOb\x8f-\xb3\x80\x87\xee\xc2\xf6\xbbM\xf1\xdf\x02K\x19\xaf\x1c\x97\xd3\x16\xc8`s\xc9r\x05\x9de\xbc+G\xf9~Tb\xa2\xe8\x02\x9a'
TEST_RSA_PRIVATE_MSKEYBLOB = '\x07\x02\x00\x00\x00\xa4\x00\x00RSA2\x00\x04\x00\x00\x01\x00\x01\x00\xd1Suu\x00\x06\x17\xa3p\x93\xce\xc9X\xe8\xad\xed\xd3G\xb5\x81/p%\x95\xfc\x02\xfb\xb8p\xf6\xa1z&x\x0f\x91G\xa6\xcd\x93\x8d\xff\xff\x84*\x14\'\xf8 \x06!\xf8"\xca\xaf\x9b3\x8bK\xb3\xdb\xda\xceX\xee\xdf\xc7\xb2\x9b\x91\xa1\xf5\xceb\x86W\xf3\x0f?\xeb\x9d\x90\x9a\x1a\x00\xbdHOb\x8f-\xb3\x80\x87\xee\xc2\xf6\xbbM\xf1\xdf\x02K\x19\xaf\x1c\x97\xd3\x16\xc8`s\xc9r\x05\x9de\xbc+G\xf9~Tb\xa2\xe8\x02\x9a\x9b\\tcH\x8aa\x01\xac\x9b\x12\x11\x8f\xc6i\x8bb\xf6XoJ{\xf9uW\x15\xcc[\x01P\xdd\x86\xd9L\xbb\xa2\x13\xc3{\xa0\xf5\xe1K\x86:\xa01h\xf4\x1a\x89\xbd?\xd4J\xc2\xc5\x9f\x9by\x9a\xb6J\xb5\x03\x9a\xd9$1U\xff\x069\x0e\x1c\xf2\xf3\xcf\x8b;\xd6\x9e%\xca\xcd\xa5\xa5\xd6\x96\xc3)E\xba\x0b\xbe\xeb9\xa2\xb4*\xffw\xb8\xf3\xc9%\x0f}\xcc\xfb\x13\x83WL\xf8\x9fh\x10_D\xde\xf2w\xe3LAz\xd9\xebc?\xc9\xf64\xbb\xea\xa4\xc2@\xfd\xf2\x1b\x04J\r\xaa\x13\x93%\x1cxD\xd6\xdc\xddl\xbb\xb1An^\x83\xe3\xdf\x15\x9f\xa9\x11\x98e-\xd1\x8f\x1c\x8fIBB\xbd\x89\x91<\xba\x12^\x85\x8a\xb3]\xcfh\xae\r~\x07lcD3\x9a9\xe7\xb5\'\xe0e1\xb6\x1c\x93\xe1\xc4+\xf4\xe51b\xf8\xed\x15\xf7h\xaa\x00\xc0]\x17^\xbd\x13\x8d\x0f\xc3\xf7E\xa6\xb8\x83\xe4`\x04\n\x80O\x90A\xe8N{~\x88\xc8\xac\xaf\x03`\x0b\x00\xff\\A\x16\xba\x86|n\x89a\xa4P\x0e\x042\xd5\xe8\xa5\xa6\x9a\x15}?Q\x08\x8e\x83I\x89\x97\xa2n\xb8X\xf4\x16D>q\x1d\xac;\x05\x8c\xc3\x8c\x18\x842\xa2]}h3D\xb8c\xf3\x14\x9aE\x949\x87\xbf\xf1P\xef\x81\xf5=\x80\xdb\xdd\x7f\xe8\xfb2J\xa7\xbc\x8a\xd6PK\x184\x07\xfd\xc0\x93\xaf\rW\xd7\x0c\xcc\x15\x7f\x19*\xd0}\x82\xdai\xaf\xa88\x86N\xbe\xaew\xa1\x97\x1coI\x16\xd4\xfb\xf1R\xce\xa8\x8eUX\xbd\x1f\x93:\x9b*\xa3p(\xdf\xc6u\xd5Rip\xa0\xfe\xd8\xebCsV:p\xc7\t\t\x06\x82i\x14\xa5\xda\xa5#-\xd5\xbb\x08(kW\xd3\xf2xM\xfa\xb7\xdf[\x1a\x1aR\xfc7\xa0\xd6\x990B'

TEST_RC4_KEY = '0123456789ABCDEF'
TEST_AES_KEY = '0123456789ABCDEF'


class TestRsaImportExport(unittest.TestCase):
    def test_rsa_public_import_export(self):
        pycrypto_key = RSA.importKey(TEST_RSA_PUBLIC_PEM)
        rsa_key = wincrypto.api.RSA_keyx(pycrypto_key)
        ms_key = rsa_key.export_publickeyblob()
        aes_key2 = wincrypto.CryptImportKey(ms_key)
        self.assertEqual(pycrypto_key, aes_key2.key)

    def test_rsa_private_import_export(self):
        pycrypto_key = RSA.importKey(TEST_RSA_PRIVATE_PEM)
        rsa_key = wincrypto.api.RSA_keyx(pycrypto_key)
        ms_key = rsa_key.export_privatekeyblob()
        aes_key2 = wincrypto.CryptImportKey(ms_key)
        self.assertEqual(pycrypto_key, aes_key2.key)

    def test_rc4_plain_export_import(self):
        rc4_key = wincrypto.api.RC4_crypt_key(TEST_RC4_KEY)
        ms_key = rc4_key.export_plaintextkeyblob()
        rc4_key = wincrypto.CryptImportKey(ms_key)
        self.assertEqual(rc4_key.key, TEST_RC4_KEY)

    def test_rc4_simple_export_import(self):
        private_key = RSA.importKey(TEST_RSA_PRIVATE_PEM)
        rc4_key = wincrypto.api.RC4_crypt_key(TEST_RC4_KEY)
        ms_key = rc4_key.export_simpleblob(private_key.publickey())
        rc4_key = wincrypto.CryptImportKey(ms_key, private_key)
        self.assertEqual(rc4_key.key, TEST_RC4_KEY)


if platform.system() == 'Windows':
    class TestRSANative(unittest.TestCase):
        TEST_STRING = 'Testing!'

        def setUp(self):
            self.hprov = native.CryptAcquireContext()
            self.hkey = native.CryptImportKey(self.hprov, TEST_RSA_PRIVATE_MSKEYBLOB)
            self.python_key = wincrypto.CryptImportKey(TEST_RSA_PRIVATE_MSKEYBLOB)

        def tearDown(self):
            native.CryptDestroyKey(self.hkey)
            native.CryptReleaseContext(self.hprov)

        def test_native_import_crypt_decrypt(self):
            c = native.CryptEncrypt(self.hkey, self.TEST_STRING)
            p2 = native.CryptDecrypt(self.hkey, c)
            self.assertEqual(self.TEST_STRING, p2)

        def test_native_encrypt_python_decrypt(self):
            c = native.CryptEncrypt(self.hkey, self.TEST_STRING)
            p2 = self.python_key.decrypt(c)
            self.assertEqual(self.TEST_STRING, p2)

        def test_python_encrypt_native_decrypt(self):
            c = self.python_key.encrypt(self.TEST_STRING)
            p2 = native.CryptDecrypt(self.hkey, c)
            self.assertEqual(self.TEST_STRING, p2)


    class TestRc4Native(unittest.TestCase):
        TEST_STRING = 'Testing!'

        def setUp(self):
            self.hprov = native.CryptAcquireContext()

        def tearDown(self):
            native.CryptReleaseContext(self.hprov)

        def test_rc4_native_plaintext_keyblob(self):
            rc4_key = wincrypto.api.RC4_crypt_key(TEST_RC4_KEY)
            key_blob = rc4_key.export_plaintextkeyblob()
            hkey = native.CryptImportKey(self.hprov, key_blob)
            c = native.CryptEncrypt(hkey, self.TEST_STRING)
            rc4_key = wincrypto.CryptImportKey(key_blob)
            p = rc4_key.decrypt(c)
            self.assertEqual(self.TEST_STRING, p)
            native.CryptDestroyKey(hkey)

        def test_rc4_native_simple_keyblob(self):
            private_key = RSA.importKey(TEST_RSA_PRIVATE_PEM)
            private_blob = wincrypto.api.RSA_keyx(private_key).export_privatekeyblob()
            rc4_key = wincrypto.api.RC4_crypt_key(TEST_RC4_KEY)
            rc4_blob = rc4_key.export_simpleblob(private_key.publickey())
            hkey_rsa = native.CryptImportKey(self.hprov, private_blob)
            hkey_rc4 = native.CryptImportKey(self.hprov, rc4_blob, hkey_rsa)
            c = native.CryptEncrypt(hkey_rc4, self.TEST_STRING)
            rc4_key = wincrypto.CryptImportKey(rc4_blob, private_key)
            p = rc4_key.decrypt(c)
            self.assertEqual(self.TEST_STRING, p)
            native.CryptDestroyKey(hkey_rc4)
            native.CryptDestroyKey(hkey_rsa)


    class TestAESNative(unittest.TestCase):
        TEST_STRING = 'Testing! Testing2 Testing3'

        def setUp(self):
            self.hprov = native.CryptAcquireContext()

        def tearDown(self):
            native.CryptReleaseContext(self.hprov)

        def test_aes_native_encrypt_python_decrypt(self):
            aes_key = wincrypto.api.AES128_crypt_key(TEST_AES_KEY)
            key_blob = aes_key.export_plaintextkeyblob()
            hkey = native.CryptImportKey(self.hprov, key_blob)
            c = native.CryptEncrypt(hkey, self.TEST_STRING)
            p = aes_key.decrypt(c)
            self.assertEqual(self.TEST_STRING, p)
            native.CryptDestroyKey(hkey)

        def test_aes_python_encrypt_native_decrypt(self):
            aes_key = wincrypto.api.AES128_crypt_key(TEST_AES_KEY)
            key_blob = aes_key.export_plaintextkeyblob()
            hkey = native.CryptImportKey(self.hprov, key_blob)
            c = aes_key.encrypt(self.TEST_STRING)
            p = native.CryptDecrypt(hkey, c)
            self.assertEqual(self.TEST_STRING, p)
            native.CryptDestroyKey(hkey)

        def test_rc4_native_simple_keyblob(self):
            private_key = RSA.importKey(TEST_RSA_PRIVATE_PEM)
            private_blob = wincrypto.api.RSA_keyx(private_key).export_privatekeyblob()
            aes_key = wincrypto.api.AES128_crypt_key(TEST_AES_KEY)
            aes_blob = aes_key.export_simpleblob(private_key.publickey())
            hkey_rsa = native.CryptImportKey(self.hprov, private_blob)
            hkey_aes = native.CryptImportKey(self.hprov, aes_blob, hkey_rsa)
            c = native.CryptEncrypt(hkey_aes, self.TEST_STRING)
            aes_key = wincrypto.CryptImportKey(aes_blob, private_key)
            p = aes_key.decrypt(c)
            self.assertEqual(self.TEST_STRING, p)
            native.CryptDestroyKey(hkey_aes)
            native.CryptDestroyKey(hkey_rsa)

if __name__ == '__main__':
    unittest.main()