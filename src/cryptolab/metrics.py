def block_match_ratio(ciphertext: bytes, block_bytes: int = 16) -> float:
    """
    Quantify ECB leakage via repeated 16-byte blocks.
    i.e. (total_blocks - unique_blocks) / total_blocks.
    :param ciphertext:
    :param block_bytes:
    :return:
    """
    pass
