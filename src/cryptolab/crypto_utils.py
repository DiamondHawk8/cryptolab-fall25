import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def pkcs7_pad(b: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to multiple of block_size.
    :param b: Block
    :param block_size: Self-describing block size
    :return: padded block
    """

    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in [1,255]")

    pad_len = block_size - (len(b) % block_size or block_size)

    return b + bytes([pad_len]) * pad_len

def pkcs7_unpad(b: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding not used , kept for completeness
    :param b: Block
    :param block_size: Self-describing block size
    :return: unpadded block
    """
    if not b or len(b) % block_size != 0:
        raise ValueError("invalid padded buffer length")

    pad_len = b[-1]
    if pad_len == 0 or pad_len > block_size or b[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad PKCS#7 padding")

    return b[:-pad_len]


def aes_ecb_encrypt(raw: bytes, key: bytes) -> bytes:
    """
    AES-ECB with cryptography library; assert len(raw)%16==0; return ciphertext.
    :param raw: Raw to encrypt
    :param key: Encryption key
    :return: CiphertextBlob
    """

    if len(raw) % 16 != 0:
        raise ValueError("raw must be multiple of 16 (pad first)")

    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 128/192/256-bit")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    return encryptor.update(raw) + encryptor.finalize()


def aes_gcm_encrypt(raw: bytes, key: bytes, nonce: bytes|None=None) -> tuple[bytes, bytes, bytes]:
    """
    AES-GCM; return (ciphertext, nonce12, tag16). Use os.urandom(12) if nonce None.
    :param raw:
    :param key:
    :param nonce:
    :return:
    """