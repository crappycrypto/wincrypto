import unittest

from Crypto.PublicKey import RSA

import wincrypto


TEST_RSA_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
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

TEST_RSA_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaAuiiYlR++UcrvGWdBXLJc2DI
FtOXHK8ZSwLf8U279sLuh4CzLY9iT0i9ABqakJ3rPw/zV4ZizvWhkZuyx9/uWM7a
27NLizObr8oi+CEGIPgnFCqE//+Nk82mR5EPeCZ6ofZwuPsC/JUlcC+BtUfT7a3o
WMnOk3CjFwYAdXVT0QIDAQAB
-----END PUBLIC KEY-----'''


class TestRsaKeys(unittest.TestCase):
    def test_rsa_public_import(self):
        pycrypto_key = RSA.importKey(TEST_RSA_PUBLIC_KEY)
        ms_key = wincrypto.rsa_to_publickeystruc(pycrypto_key)
        pycrypto_key2 = wincrypto.import_publickeystruc(ms_key)
        self.assertEqual(pycrypto_key, pycrypto_key2)

    def test_rsa_private_import(self):
        pycrypto_key = RSA.importKey(TEST_RSA_PRIVATE_KEY)
        ms_key = wincrypto.rsa_to_privatekeystruc(pycrypto_key)
        pycrypto_key2 = wincrypto.import_publickeystruc(ms_key)
        self.assertEqual(pycrypto_key, pycrypto_key2)


if __name__ == '__main__':
    unittest.main()