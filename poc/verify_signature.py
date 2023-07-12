import binascii
import hashlib
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import ecdsa.util

def verify_signature(pub_key, message, signature):
    try:
        vk = VerifyingKey.from_string(binascii.unhexlify(pub_key), curve=SECP256k1)
        return vk.verify(binascii.unhexlify(signature), message.encode(), sigdecode=ecdsa.util.sigdecode_der, hashfunc=hashlib.sha256)
    except BadSignatureError:
        return False

message = 'Some host-hashed data...'
pub_key = '04a8209102092c36ab4eed0323cdacb1b9c4eb451c734c50fa88ddd8b57639c327463276e9528c369f80d7dde20ea895e06893c455a5ce6f9d6044ef1cfab3fb9b'
signature = '3045022075ce1c5bbe117568916f25a19624eccd2d7e87885ac1282585ec734a55b682d202210095807f78f99188a769e0c6905e017a229452c9f12f6226f029c2bf0393d5196c'

if verify_signature(pub_key, message, signature):
    print("The signature is valid.")
else:
    print("The signature is not valid.")
