from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from base64 import b64decode, b64encode
import hashlib


def b64dec(s):
    return b64decode(s.encode("ascii") + b"==", b"-_")


def b64enc(s):
    return b64encode(s, b"-_").strip(b" =\n").decode("ascii")


def pad(s: bytes):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16).encode('ascii')


def unpad(s):
    if len(s) % 16:
        raise ValueError('unpadded byte string')
    return s[:-s[-1]]


def unmerge_key_iv(filebit_key):
    data = b64dec(filebit_key)
    version = data[0]
    if version != 1 or len(data) != 33:
        raise NotImplementedError("unknown version or key")
    key = data[2::2]
    iv = data[1::2]
    return key, iv


def merge_key_iv(key: bytes, iv: bytes):
    return b64enc(b'\1' + b"".join(b'%c%c' % (b, a) for a, b in zip(key, iv)))


def name_key_size_hash(name: bytes, key: bytes, size):
    assert isinstance(name, bytes)
    assert isinstance(key, bytes)
    key_b64 = b64enc(key).encode("ascii")
    nkh = hashlib.sha256(key_b64)
    nkh.update(name)
    nkh.update(key_b64)
    return hashlib.sha256(b'{n:%b:s%d:k%b}%s' % (name, size, key_b64, nkh.hexdigest().encode('ascii'))).hexdigest()


class FilebitCipher(Cipher):
    def __init__(self, filebit_key=None, key=None, iv=None):
        if not key and not iv:
            key, iv = unmerge_key_iv(filebit_key)
        assert len(key) == 16
        assert len(iv) == 16
        super().__init__(AES(key), CBC(iv))
