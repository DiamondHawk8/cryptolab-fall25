import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


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
        raise ValueError("the raw must be multiple of 16 (pad first ykyk)")

    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 128/192/256-bit")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    return encryptor.update(raw) + encryptor.finalize()


def aes_gcm_encrypt(raw: bytes, key: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """
    AES-GCM; return (ciphertext, nonce12, tag16). Use os.urandom(12) if nonce None.
    :param raw:
    :param key:
    :param nonce:
    :return:
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 128/192/256-bit")

    if nonce is None:
        nonce = os.urandom(12)

    elif len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")

    aead = AESGCM(key)

    ct_plus_tag = aead.encrypt(nonce, raw, associated_data=None)

    # Split off the last 16 bytes (tag)
    if len(ct_plus_tag) < 16:
        raise RuntimeError("unexpected GCM output size")

    return ct_plus_tag[:-16], nonce, ct_plus_tag[-16:]


def chacha20poly1305_encrypt(raw: bytes, key: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """
    ChaCha20-Poly1305; return (ciphertext, nonce12, tag16). Uses os.urandom(12) if nonce None.
    :param raw: Data to encrypt
    :param key: Key must be 32 bytes. Nonce must be 12 bytes (IETF variant).
    :param nonce: Nonce
    :return:
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 256-bit (32 bytes)")

    if nonce is None:
        nonce = os.urandom(12)
    elif len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")

    aead = ChaCha20Poly1305(key)
    ct_plus_tag = aead.encrypt(nonce, raw, associated_data=None)

    if len(ct_plus_tag) < 16:
        raise RuntimeError("unexpected ChaCha20-Poly1305 output size")

    return ct_plus_tag[:-16], nonce, ct_plus_tag[-16:]


def aes_ctr_keystream(nbytes: int, key: bytes, iv: bytes) -> bytes:
    """
    Generate nbytes of keystream using AES-CTR by encrypting a zero buffer.
    AES-CTR uses a 16-byte (128-bit) IV/initial counter.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-CTR key must be 128/192/256-bit")
    if len(iv) != 16:
        raise ValueError("AES-CTR IV must be 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00" * nbytes) + encryptor.finalize()


def aes_ctr_encrypt(raw: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-CTR encryption: raw ⊕ keystream. Returns ciphertext (no tag).
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-CTR key must be 128/192/256-bit")
    if len(iv) != 16:
        raise ValueError("AES-CTR IV must be 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(raw) + encryptor.finalize()
