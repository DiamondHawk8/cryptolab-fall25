def run_reuse_demo(mode: str, in1_path: str, in2_path: str, algo: str = "aesgcm", key_hex: str | None = None,
                   nonce_hex: str | None = None, danger: bool = False) -> None:
    """

    :param mode: "attack" reuses a single nonce for two encryptions, "patched" uses distinct nonces.
    :param in1_path: Input blob 1
    :param in2_path: Input blob 2
    :param algo: Encryption/Decryption algorithm (AES-GCM or ChaCha20-Poly1305).
    :param key_hex:
    :param nonce_hex:
    :param danger:
    :return:
    """
    pass

def xor_ciphertexts(ct1: bytes, ct2: bytes) -> bytes:
    """
    Return ct1 ⊕ ct2 up to min length; mirrors pt1 ⊕ pt2 when nonce is reused.
    :param ct1: Ciphertext 1
    :param ct2: Ciphertext 2
    :return: ct1 ⊕ ct2
    """