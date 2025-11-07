from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Tuple

from src.cryptolab.attacks.nonce_reuse import xor_bytes, ascii_crib_drag_fraction
from src.cryptolab.crypto_utils import aes_gcm_encrypt, chacha20poly1305_encrypt
from src.cryptolab.logging_utils import ensure_logger, emit_json

REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / "assets"
LOGS = REPO / "logs"
OUTPUTS = REPO / "outputs"
OUTPUTS.mkdir(parents=True, exist_ok=True)
LOGS.mkdir(parents=True, exist_ok=True)

DEFAULT_IN1 = ASSETS / "nonce_reuse_1.txt"
DEFAULT_IN2 = ASSETS / "nonce_reuse_2.txt"

# Single rotating JSONL logger
LOGGER = ensure_logger(str(LOGS), "metrics.jsonl", level="INFO")


def parse_hex(s: str) -> bytes:

    s = s.strip().lower().replace("0x", "").replace(" ", "")

    if len(s) % 2 != 0:
        raise argparse.ArgumentTypeError("hex must have even length")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid hex: {e}")


def read_bytes(path: Path) -> bytes:
    return Path(path).read_bytes()


def choose_key(algo: str, key_hex: bytes | None) -> bytes:
    # AES-GCM and ChaCha20-Poly1305 demos both use 32B keys here.
    return key_hex if key_hex is not None else os.urandom(32)


def encrypt_pair(algo: str, key: bytes, pt1: bytes, pt2: bytes, reuse_nonce: bool, forced_nonce: bytes | None) \
        -> Tuple[Tuple[bytes, bytes, bytes], Tuple[bytes, bytes, bytes]]:
    """
    Returns ((ct1, nonce1, tag1), (ct2, nonce2, tag2)).
    :param algo: Encryption algorithm to use
    :param key: Encryption key to use
    :param pt1: Plaintext 1
    :param pt2: Plaintext 2
    :param reuse_nonce: If True, both encryptions use the same nonce (attack).
    :param forced_nonce: If provided, it is used for (both) in attack mode; ignored in patched mode.
    :return:
    """
    if algo not in ("aesgcm", "chacha20"):
        raise ValueError("algo must be 'aesgcm' or 'chacha20'")

    if reuse_nonce:
        nonce = forced_nonce if forced_nonce is not None else os.urandom(12)
        if algo == "aesgcm":
            ct1, n1, tag1 = aes_gcm_encrypt(pt1, key, nonce=nonce)
            ct2, n2, tag2 = aes_gcm_encrypt(pt2, key, nonce=nonce)
        else:
            ct1, n1, tag1 = chacha20poly1305_encrypt(pt1, key, nonce=nonce)
            ct2, n2, tag2 = chacha20poly1305_encrypt(pt2, key, nonce=nonce)
    else:
        if algo == "aesgcm":
            ct1, n1, tag1 = aes_gcm_encrypt(pt1, key, nonce=None)
            ct2, n2, tag2 = aes_gcm_encrypt(pt2, key, nonce=None)
        else:
            ct1, n1, tag1 = chacha20poly1305_encrypt(pt1, key, nonce=None)
            ct2, n2, tag2 = chacha20poly1305_encrypt(pt2, key, nonce=None)

    return (ct1, n1, tag1), (ct2, n2, tag2)


def write_bundle(out: Path, mode: str, algo: str, pair1: Tuple[bytes, bytes, bytes], pair2: Tuple[bytes, bytes, bytes],
                 note: str) -> tuple[Path, Path]:
    """
    Save combined binary and meta JSON:
    - .bin layout: [ct1|tag1|ct2|tag2]
    - .meta.json: algo, nonce(s), lengths, layout, note
    :param out:
    :param mode:
    :param algo:
    :param pair1:
    :param pair2:
    :param note:
    :return:
    """
    ct1, n1, tag1 = pair1
    ct2, n2, tag2 = pair2

    base = f"reuse_{mode}"
    bin_path = out / f"{base}.bin"
    meta_path = out / f"{base}.meta.json"

    with bin_path.open("wb") as fh:
        fh.write(ct1 + tag1 + ct2 + tag2)

    meta = {
        "algo": algo,
        "nonce_hex" if n1 == n2 else "nonce_hexes": (n1.hex() if n1 == n2 else [n1.hex(), n2.hex()]),
        "ct1_len": len(ct1),
        "ct2_len": len(ct2),
        "tag_len": len(tag1),
        "layout": "[ct1|tag1|ct2|tag2]",
        "note": note,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return bin_path, meta_path


def log_run(mode: str, algo: str, pair1: Tuple[bytes, bytes, bytes], pair2: Tuple[bytes, bytes, bytes], xor_len: int,
            match_fraction: float, note: str) -> None:
    ct1, n1, tag1 = pair1
    ct2, n2, tag2 = pair2

    payload = {
        "module": "reuse",
        "mode": mode,
        "metrics": {
            "algo": algo,
            "bytes": {"ct1": len(ct1), "ct2": len(ct2), "tag": len(tag1)},
            "nonce_reused": (n1 == n2),
            "nonce_hex" if n1 == n2 else "nonce_hexes": (n1.hex() if n1 == n2 else [n1.hex(), n2.hex()]),
            "xor_len": xor_len,
            "bytes_recovered": xor_len,
            "match_fraction": round(match_fraction, 4),
            "note": note,
        }
    }
    emit_json(LOGGER, payload)


def main():
    ap = argparse.ArgumentParser(description="IV/Nonce Reuse demo (AES-GCM / ChaCha20-Poly1305).")
    ap.add_argument("--mode", choices=["attack", "patched"], required=True)
    ap.add_argument("--algo", choices=["aesgcm", "chacha20"], default="aesgcm")
    ap.add_argument("--in1", type=str, default=str(DEFAULT_IN1),
                    help="First plaintext file (default assets/nonce_reuse_1.txt)")
    ap.add_argument("--in2", type=str, default=str(DEFAULT_IN2),
                    help="Second plaintext file (default assets/nonce_reuse_2.txt)")
    ap.add_argument("--key-hex", type=parse_hex, default=None)
    ap.add_argument("--nonce-hex", type=parse_hex, default=None, help="12-byte nonce; used in attack mode only")
    ap.add_argument("--out", type=str, default=str(OUTPUTS))
    ap.add_argument("--danger-educational", action="store_true", help="Required to run attack mode")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.mode == "attack" and not args.danger_educational:
        print("Refusing to run attack without --danger-educational flag.", file=sys.stderr)
        return 2

    # Load inputs
    pt1 = read_bytes(Path(args.in1))
    pt2 = read_bytes(Path(args.in2))

    # Choose key + nonce policy
    key = choose_key(args.algo, args.key_hex)

    reuse_nonce = (args.mode == "attack")
    forced_nonce = args.nonce_hex if reuse_nonce else None  # ignore in patched mode

    # Encrypt both messages under selected algorithm
    pair1, pair2 = encrypt_pair(args.algo, key, pt1, pt2, reuse_nonce=reuse_nonce, forced_nonce=forced_nonce)

    # XOR of ciphertexts (mirrors XOR of plaintexts only when nonce reused)
    ct1, n1, tag1 = pair1
    ct2, n2, tag2 = pair2
    xor_ct = xor_bytes(ct1, ct2)

    if reuse_nonce:
        note = "Reused nonce causes keystream reuse; ct1⊕ct2 = pt1⊕pt2 (danger: educational)."
        xor_len = len(xor_ct)
        match_frac = ascii_crib_drag_fraction(xor_ct)
    else:
        note = "Unique nonces per message; xor-of-cts does not mirror xor-of-pts."
        xor_len = 0
        match_frac = 0.0

    # Save artifacts and log
    write_bundle(out, mode=args.mode, algo=args.algo, pair1=pair1, pair2=pair2, note=note)
    log_run(args.mode, args.algo, pair1, pair2, xor_len=xor_len, match_fraction=match_frac, note=note)

    print(f"[reuse:{args.mode}] algo={args.algo} xor_len={xor_len} match_fraction={match_frac:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
