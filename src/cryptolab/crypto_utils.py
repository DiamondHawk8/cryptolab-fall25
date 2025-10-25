def pkcs7_pad(b: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to multiple of block_size.
    :param b:
    :param block_size:
    :return:
    """

def aes_ecb_encrypt(raw: bytes, key: bytes) -> bytes:
    """
    AES-ECB with cryptography library; assert len(raw)%16==0; return ciphertext.
    :param raw:
    :param key:
    :return:
    """


def aes_gcm_encrypt(raw: bytes, key: bytes, nonce: bytes|None=None) -> tuple[bytes, bytes, bytes]:
    """
    AES-GCM; return (ciphertext, nonce12, tag16). Use os.urandom(12) if nonce None.
    :param raw:
    :param key:
    :param nonce:
    :return:
    """