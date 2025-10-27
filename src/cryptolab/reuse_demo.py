from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from typing import Tuple
from logging_utils import emit_json


try:
    from logging_utils import emit_json
except Exception:
    emit_json = None  # fallback below

from .crypto_utils import (
    aes_gcm_encrypt,
    chacha20poly1305_encrypt,
)

from attacks.nonce_reuse import xor_bytes, ascii_crib_drag_fraction



def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings up to min(len(a), len(b)).
    :param a: byte 1
    :param b: byte 2
    :return: a ⊕ b
    """
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))