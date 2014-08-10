from ctypes import windll, c_void_p, byref, create_string_buffer, c_int

PROV_RSA_FULL = 1
PROV_RSA_AES = 24


def CryptAcquireContext():
    hprov = c_void_p()
    success = windll.advapi32.CryptAcquireContextA(byref(hprov), 0, 0, PROV_RSA_FULL, 0)
    assert success
    return hprov


def CryptReleaseContext(hprov):
    success = windll.advapi32.CryptReleaseContext(hprov, 0)
    assert success


def CryptImportKey(hprov, keyblob):
    hkey = c_void_p()
    success = windll.advapi32.CryptImportKey(hprov, keyblob, len(keyblob), 0, 0, byref(hkey))
    assert success
    return hkey


def CryptDestroyKey(hkey):
    success = windll.advapi32.CryptDestroyKey(hkey)
    assert success


def CryptDecrypt(hkey, encrypted_data):
    bdata = create_string_buffer(encrypted_data)
    bdatalen = c_int(len(encrypted_data))
    result = windll.advapi32.CryptDecrypt(hkey, 0, 1, 0, bdata, byref(bdatalen))
    assert result == 1
    return bdata.raw[:bdatalen.value]


def CryptEncrypt(hkey, plain_data):
    # determine output buffer length
    bdatalen_test = c_int(len(plain_data))
    success = windll.advapi32.CryptEncrypt(hkey, 0, 1, 0, 0, byref(bdatalen_test), len(plain_data))
    assert success
    out_buf_len = bdatalen_test.value

    # encrypt data
    bdata = create_string_buffer(plain_data, out_buf_len)
    bdatalen = c_int(len(plain_data))
    success = windll.advapi32.CryptEncrypt(hkey, 0, 1, 0, bdata, byref(bdatalen), out_buf_len)
    assert success
    return bdata.raw[:bdatalen.value]
