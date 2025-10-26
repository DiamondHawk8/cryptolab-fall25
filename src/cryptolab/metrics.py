def block_match_ratio(ciphertext: bytes, block_bytes: int = 16):
    """
    Quantify ECB leakage via repeated 16-byte blocks.
    i.e. (total_blocks - unique_blocks) / total_blocks.
    :param ciphertext:
    :param block_bytes:
    :return:
    """
    if block_bytes <= 0:
        raise ValueError("block_bytes must be positive")

    if len(ciphertext) % block_bytes != 0:
        raise ValueError("ciphertext length must be multiple of block size")

    total = len(ciphertext) // block_bytes
    blocks = (ciphertext[i:i + block_bytes] for i in range(0, len(ciphertext), block_bytes))
    unique = len(set(blocks))
    identical = total - unique

    ratio = identical / total if total else 0.0

    return identical, total, ratio
