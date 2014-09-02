import platform

if platform.system() == 'Windows':
    import unittest
    from wincrypto import native, constants, api
    import wincrypto
    from wincrypto.algorithms import symmetric_algorithms, hash_algorithms
    import wincrypto.api
    from wincrypto.constants import bType_PLAINTEXTKEYBLOB, bType_SIMPLEBLOB, bType_PRIVATEKEYBLOB, KP_ALGID, \
        KP_KEYLEN, HP_HASHSIZE, HP_ALGID

    from binascii import a2b_hex


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

    TEST_RSA_PUBLIC_MSKEYBLOB = a2b_hex(
        b'0602000000a40000525341310004000001000100d1537575000617a37093cec958e8adedd347b5812f'
        b'702595fc02fbb870f6a17a26780f9147a6cd938dffff842a1427f8200621f822caaf9b338b4bb3dbda'
        b'ce58eedfc7b29b91a1f5ce628657f30f3feb9d909a1a00bd484f628f2db38087eec2f6bb4df1df024b'
        b'19af1c97d316c86073c972059d65bc2b47f97e5462a2e8029a')
    TEST_RSA_PRIVATE_MSKEYBLOB = b'\x07\x02\x00\x00\x00\xa4\x00\x00RSA2\x00\x04\x00\x00\x01\x00\x01\x00\xd1Suu\x00\x06\x17\xa3p\x93\xce\xc9X\xe8\xad\xed\xd3G\xb5\x81/p%\x95\xfc\x02\xfb\xb8p\xf6\xa1z&x\x0f\x91G\xa6\xcd\x93\x8d\xff\xff\x84*\x14\'\xf8 \x06!\xf8"\xca\xaf\x9b3\x8bK\xb3\xdb\xda\xceX\xee\xdf\xc7\xb2\x9b\x91\xa1\xf5\xceb\x86W\xf3\x0f?\xeb\x9d\x90\x9a\x1a\x00\xbdHOb\x8f-\xb3\x80\x87\xee\xc2\xf6\xbbM\xf1\xdf\x02K\x19\xaf\x1c\x97\xd3\x16\xc8`s\xc9r\x05\x9de\xbc+G\xf9~Tb\xa2\xe8\x02\x9a\x9b\\tcH\x8aa\x01\xac\x9b\x12\x11\x8f\xc6i\x8bb\xf6XoJ{\xf9uW\x15\xcc[\x01P\xdd\x86\xd9L\xbb\xa2\x13\xc3{\xa0\xf5\xe1K\x86:\xa01h\xf4\x1a\x89\xbd?\xd4J\xc2\xc5\x9f\x9by\x9a\xb6J\xb5\x03\x9a\xd9$1U\xff\x069\x0e\x1c\xf2\xf3\xcf\x8b;\xd6\x9e%\xca\xcd\xa5\xa5\xd6\x96\xc3)E\xba\x0b\xbe\xeb9\xa2\xb4*\xffw\xb8\xf3\xc9%\x0f}\xcc\xfb\x13\x83WL\xf8\x9fh\x10_D\xde\xf2w\xe3LAz\xd9\xebc?\xc9\xf64\xbb\xea\xa4\xc2@\xfd\xf2\x1b\x04J\r\xaa\x13\x93%\x1cxD\xd6\xdc\xddl\xbb\xb1An^\x83\xe3\xdf\x15\x9f\xa9\x11\x98e-\xd1\x8f\x1c\x8fIBB\xbd\x89\x91<\xba\x12^\x85\x8a\xb3]\xcfh\xae\r~\x07lcD3\x9a9\xe7\xb5\'\xe0e1\xb6\x1c\x93\xe1\xc4+\xf4\xe51b\xf8\xed\x15\xf7h\xaa\x00\xc0]\x17^\xbd\x13\x8d\x0f\xc3\xf7E\xa6\xb8\x83\xe4`\x04\n\x80O\x90A\xe8N{~\x88\xc8\xac\xaf\x03`\x0b\x00\xff\\A\x16\xba\x86|n\x89a\xa4P\x0e\x042\xd5\xe8\xa5\xa6\x9a\x15}?Q\x08\x8e\x83I\x89\x97\xa2n\xb8X\xf4\x16D>q\x1d\xac;\x05\x8c\xc3\x8c\x18\x842\xa2]}h3D\xb8c\xf3\x14\x9aE\x949\x87\xbf\xf1P\xef\x81\xf5=\x80\xdb\xdd\x7f\xe8\xfb2J\xa7\xbc\x8a\xd6PK\x184\x07\xfd\xc0\x93\xaf\rW\xd7\x0c\xcc\x15\x7f\x19*\xd0}\x82\xdai\xaf\xa88\x86N\xbe\xaew\xa1\x97\x1coI\x16\xd4\xfb\xf1R\xce\xa8\x8eUX\xbd\x1f\x93:\x9b*\xa3p(\xdf\xc6u\xd5Rip\xa0\xfe\xd8\xebCsV:p\xc7\t\t\x06\x82i\x14\xa5\xda\xa5#-\xd5\xbb\x08(kW\xd3\xf2xM\xfa\xb7\xdf[\x1a\x1aR\xfc7\xa0\xd6\x990B'

    TEST_DATA = bytes(bytearray(range(64)))  # 64 is a multiple of most blocksizes


    class TestSymmetricNative(unittest.TestCase):
        def setUp(self):
            self.hprov = native.CryptAcquireContext()

        def tearDown(self):
            native.CryptReleaseContext(self.hprov)

        def test_native_plaintextkeyblob(self):
            for algorithm in symmetric_algorithms:
                instance = algorithm('A' * algorithm.key_len)
                blob = wincrypto.api.CryptExportKey(instance, None, bType_PLAINTEXTKEYBLOB)
                hkey = native.CryptImportKey(self.hprov, blob)
                c = native.CryptEncrypt(hkey, TEST_DATA)
                p = instance.decrypt(c)
                native.CryptDestroyKey(hkey)
                self.assertEqual(TEST_DATA, p)

        def test_native_simplekeyblob(self):
            rsa_key = wincrypto.algorithms.RSA_KEYX.from_pem(TEST_RSA_PRIVATE_PEM)
            rsa_blob = wincrypto.api.CryptExportKey(rsa_key, None, bType_PRIVATEKEYBLOB)
            rsa_hkey = native.CryptImportKey(self.hprov, rsa_blob)
            for algorithm in symmetric_algorithms:
                instance = algorithm(b'A' * algorithm.key_len)
                blob = wincrypto.api.CryptExportKey(instance, rsa_key, bType_SIMPLEBLOB)
                hkey = native.CryptImportKey(self.hprov, blob, rsa_hkey)
                c = native.CryptEncrypt(hkey, TEST_DATA)
                p = instance.decrypt(c)
                native.CryptDestroyKey(hkey)
                self.assertEqual(TEST_DATA, p)
            native.CryptDestroyKey(rsa_hkey)

        def test_native_plaintextkeyblob(self):
            for algorithm in symmetric_algorithms:
                instance = algorithm(b'A' * algorithm.key_len)
                blob = wincrypto.api.CryptExportKey(instance, None, bType_PLAINTEXTKEYBLOB)
                hkey = native.CryptImportKey(self.hprov, blob)
                for key_param in [KP_ALGID, KP_KEYLEN]:
                    native_val = native.CryptGetKeyParam(hkey, key_param)
                    python_val = api.CryptGetKeyParam(instance, key_param)
                    self.assertEqual(native_val, python_val)
                native.CryptDestroyKey(hkey)


    class TestRSANative(unittest.TestCase):
        def setUp(self):
            self.hprov = native.CryptAcquireContext()
            self.hkey = native.CryptImportKey(self.hprov, TEST_RSA_PRIVATE_MSKEYBLOB)
            self.python_key = wincrypto.CryptImportKey(TEST_RSA_PRIVATE_MSKEYBLOB)

        def tearDown(self):
            native.CryptDestroyKey(self.hkey)
            native.CryptReleaseContext(self.hprov)

        def test_native_import_crypt_decrypt(self):
            c = native.CryptEncrypt(self.hkey, TEST_DATA)
            p2 = native.CryptDecrypt(self.hkey, c)
            self.assertEqual(TEST_DATA, p2)

        def test_native_encrypt_python_decrypt(self):
            c = native.CryptEncrypt(self.hkey, TEST_DATA)
            p2 = self.python_key.decrypt(c)
            self.assertEqual(TEST_DATA, p2)

        def test_python_encrypt_native_decrypt(self):
            c = self.python_key.encrypt(TEST_DATA)
            p2 = native.CryptDecrypt(self.hkey, c)
            self.assertEqual(TEST_DATA, p2)

    class TestHashNative(unittest.TestCase):
        def setUp(self):
            self.hprov = native.CryptAcquireContext()

        def tearDown(self):
            native.CryptReleaseContext(self.hprov)

        def test_hash_native_python(self):
            for algorithm in hash_algorithms:
                hCryptHash = native.CryptCreateHash(self.hprov, algorithm.alg_id)
                native.CryptHashData(hCryptHash, TEST_DATA)
                native_hash_val = native.CryptGetHashParam(hCryptHash, constants.HP_HASHVAL)
                native_hash_size = native.CryptGetHashParam(hCryptHash, HP_HASHSIZE)
                native_hash_algid = native.CryptGetHashParam(hCryptHash, HP_ALGID)
                native.CryptDestroyHash(hCryptHash)

                md5_hash = wincrypto.api.CryptCreateHash(algorithm.alg_id)
                wincrypto.api.CryptHashData(md5_hash, TEST_DATA)
                python_hash = wincrypto.api.CryptGetHashParam(md5_hash, constants.HP_HASHVAL)
                python_hash_size = wincrypto.api.CryptGetHashParam(md5_hash, HP_HASHSIZE)
                python_hash_algid = wincrypto.api.CryptGetHashParam(md5_hash, HP_ALGID)

                self.assertEqual(python_hash, native_hash_val)
                self.assertEqual(python_hash_size, native_hash_size)
                self.assertEqual(python_hash_algid, native_hash_algid)


    class TestCryptDeriveKeyNative(unittest.TestCase):
        def setUp(self):
            self.hprov = native.CryptAcquireContext()

        def tearDown(self):
            native.CryptReleaseContext(self.hprov)

        def test_CryptDeriveKey_native_python(self):
            for hash_alg in hash_algorithms:
                for sym_alg in symmetric_algorithms:
                    hCryptHash = native.CryptCreateHash(self.hprov, hash_alg.alg_id)
                    native.CryptHashData(hCryptHash, TEST_DATA)
                    derived_hcrypt = native.CryptDeriveKey(self.hprov, sym_alg.alg_id, hCryptHash)
                    native_key_blob = native.CryptExportKey(derived_hcrypt, 0, bType_PLAINTEXTKEYBLOB)
                    native.CryptDestroyHash(hCryptHash)
                    native_key = api.CryptImportKey(native_key_blob)

                    python_hash = api.CryptCreateHash(hash_alg.alg_id)
                    api.CryptHashData(python_hash, TEST_DATA)
                    python_key = api.CryptDeriveKey(python_hash, sym_alg.alg_id)

                    self.assertEqual(native_key.key, python_key.key)
