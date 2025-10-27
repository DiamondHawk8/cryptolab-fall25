def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings up to min(len(a), len(b)).
    :param a: string1
    :param b: string2
    :return: XORed string
    """
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def ascii_crib_drag_fraction(x: bytes) -> float:
    """
    Tiny heuristic for demos: fraction of XOR bytes that land in 'printable-ish' ASCII.
    This is not an attack metric—just a visual .
    :param x:
    :return:
    """
    if not x:
        return 0.0
    printable = sum(1 for b in x if 0x09 == b or 0x20 <= b <= 0x7E)  # tab or visible ASCII
    return printable / len(x)