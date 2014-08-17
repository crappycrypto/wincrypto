from wincrypto.algorithms import algorithm_registry
from wincrypto.definitions import PUBLICKEYSTRUC, PUBLICKEYSTRUC_s, CUR_BLOB_VERSION, bType_PUBLICKEYBLOB, \
    bType_PRIVATEKEYBLOB, bType_PLAINTEXTKEYBLOB, bType_SIMPLEBLOB


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