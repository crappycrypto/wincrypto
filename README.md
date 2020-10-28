wincrypto
=========

Windows Crypto API compatible decryption/encryption for python. The targeted crypto provider is PROV_RSA_AES.

Implemented algorithms:

 - CALG_RC4
 - CALG_AES128 
 - CALG_AES192
 - CALG_AES256
 - CALG_RSA_KEYX
 - CALG_MD5
 - CALG_SHA1 
 - CALG_SHA256
 
Implemented functions:

 - CryptImportKey
 - CryptExportKey
 - CryptEncrypt
 - CryptDecrypt
 - CryptGetKeyParam (incomplete)
 - CryptCreateHash
 - CryptHashData
 - CryptGetHashParam
 - CryptDeriveKey
  
An example of how to use this package:
  
```python  
from wincrypto import CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptImportKey, CryptExportKey
from wincrypto.constants import CALG_SHA1, CALG_AES_256, bType_SIMPLEBLOB
            
#derive key from password
sha1_hasher = CryptCreateHash(CALG_SHA1)
CryptHashData(sha1_hasher, 'Password')
aes_key = CryptDeriveKey(sha1_hasher, CALG_AES_256)

#encrypt data using key
encrypted_data = CryptEncrypt(aes_key, 'secret data')

#Import a PUBLICKEYBLOB and export the AES key as SIMPLEBLOB
TEST_RSA_PUBLIC_MSKEYBLOB = '0602000000a40000525341310004000001000100d1537575000617a37093cec958e8adedd347b5812f' \
                            '702595fc02fbb870f6a17a26780f9147a6cd938dffff842a1427f8200621f822caaf9b338b4bb3dbda' \
                            'ce58eedfc7b29b91a1f5ce628657f30f3feb9d909a1a00bd484f628f2db38087eec2f6bb4df1df024b' \
                            '19af1c97d316c86073c972059d65bc2b47f97e5462a2e8029a'.decode('hex')              
rsa_pub_key = CryptImportKey(TEST_RSA_PUBLIC_MSKEYBLOB)
encrypted_aes_key = CryptExportKey(aes_key, rsa_pub_key, bType_SIMPLEBLOB)
```

[![Build Status](https://travis-ci.org/crappycrypto/wincrypto.png)](https://travis-ci.org/crappycrypto/wincrypto)
