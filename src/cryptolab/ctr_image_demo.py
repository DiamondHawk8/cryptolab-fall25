from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PIL import Image, ImageOps

from crypto_utils import aes_ctr_keystream
from logging_utils import ensure_logger, emit_json

REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / "assets"
LOGS = REPO / "logs"
OUTPUTS = REPO / "outputs"
OUTPUTS.mkdir(parents=True, exist_ok=True)
LOGS.mkdir(parents=True, exist_ok=True)
LOGGER = ensure_logger(str(LOGS), "metrics.jsonl", level="INFO")

NOISE_BIN = OUTPUTS / "ctr_noise.bin"
NOISE_META = OUTPUTS / "ctr_noise.meta.json"
CT1_BIN = OUTPUTS / "ctr_ct1.bin"
CT1_PNG = OUTPUTS / "ctr_ct1.png"
CT2_BIN = OUTPUTS / "ctr_ct2.bin"
CT2_PNG = OUTPUTS / "ctr_ct2.png"
XOR_CT_PNG = OUTPUTS / "ctr_xor_ct.png"
XOR_PLAIN_PNG = OUTPUTS / "ctr_xor_plain.png"
RECOVERED2_PNG = OUTPUTS / "ctr_recovered2.png"
RECOVERED1_PNG = OUTPUTS / "ctr_recovered1.png"


def parse_hex(s: str) -> bytes:
    s = s.strip().lower().replace("0x", "").replace(" ", "")
    if len(s) % 2 != 0:
        raise argparse.ArgumentTypeError("hex must have even length")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid hex: {e}")


def load_square_rgb(img_path: Path, size: int) -> Image.Image:
    im = Image.open(img_path)
    im = ImageOps.exif_transpose(im).convert("RGB")
    w, h = im.size
    m = min(w, h)
    left = (w - m) // 2
    top = (h - m) // 2
    im = im.crop((left, top, left + m, top + m)).resize((size, size), Image.LANCZOS)
    return im


def xor_bytes(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def save_bytes_as_png(raw: bytes, w: int, h: int, out_path: Path) -> None:
    Image.frombytes("RGB", (w, h), raw).save(out_path)


def save_noise_meta(key_hex: str, iv_hex: str, w: int, h: int) -> None:
    meta = {"algo": "aes-ctr", "key_len": len(bytes.fromhex(key_hex)),
            "iv_hex": iv_hex, "img": {"w": w, "h": h, "channels": 3}, "nbytes": w * h * 3}
    NOISE_META.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def read_noise_meta() -> dict:
    return json.loads(NOISE_META.read_text(encoding="utf-8"))


def cmd_noise(args):
    # Decide size from --ref or --size
    if args.ref:
        im = load_square_rgb(Path(args.ref), args.size or 512)
        w = h = im.size[0]
    else:
        if not args.size:
            raise SystemExit("--size is required when --ref is not provided")
        w = h = args.size

    nbytes = w * h * 3
    key = args.key_hex if args.key_hex is not None else os.urandom(32)
    iv = args.iv_hex if args.iv_hex is not None else os.urandom(16)

    ks = aes_ctr_keystream(nbytes, key, iv)
    NOISE_BIN.write_bytes(ks)
    save_bytes_as_png(ks, w, h, OUTPUTS / "ctr_noise.png")
    save_noise_meta(key.hex(), iv.hex(), w, h)

    emit_json(LOGGER, {
        "module": "reuse", "mode": "img_noise",
        "metrics": {"step": "noise", "algo": "aes-ctr", "img": {"w": w, "h": h, "channels": 3},
                    "bytes": {"keystream": nbytes}, "iv_hex": iv.hex(),
                    "note": "Generated AES-CTR keystream (noise) for image-sized buffer."}
    })
    print(f"[ctrimg:noise] wrote {NOISE_BIN.name} ({nbytes} bytes) and ctr_noise.png")


def cmd_apply(args, which: int):
    meta = read_noise_meta()
    w = meta["img"]["w"]
    h = meta["img"]["h"]
    ks = NOISE_BIN.read_bytes()
    # Load image and normalize to noise dimensions
    src = Path(args.img)
    im = load_square_rgb(src, w)
    pt = im.tobytes()
    if len(pt) != len(ks):
        raise SystemExit("normalized image size does not match noise length")
    ct = xor_bytes(pt, ks)
    if which == 1:
        CT1_BIN.write_bytes(ct)
        save_bytes_as_png(ct, w, h, CT1_PNG)
        emit_json(LOGGER, {"module": "reuse", "mode": "img_apply1",
                           "metrics": {"step": "apply1", "bytes": {"pt": len(pt), "ct": len(ct)},
                                       "iv_hex": meta["iv_hex"], "note": "ct1 = pt1 ⊕ keystream"}})
        print(f"[ctrimg:apply1] wrote {CT1_BIN.name}, {CT1_PNG.name}")
    else:
        CT2_BIN.write_bytes(ct)
        save_bytes_as_png(ct, w, h, CT2_PNG)
        emit_json(LOGGER, {"module": "reuse", "mode": "img_apply2",
                           "metrics": {"step": "apply2", "bytes": {"pt": len(pt), "ct": len(ct)},
                                       "iv_hex": meta["iv_hex"], "note": "ct2 = pt2 ⊕ keystream"}})
        print(f"[ctrimg:apply2] wrote {CT2_BIN.name}, {CT2_PNG.name}")


def cmd_combine(args):
    meta = read_noise_meta()
    w = meta["img"]["w"]
    h = meta["img"]["h"]
    ct1 = CT1_BIN.read_bytes()
    ct2 = CT2_BIN.read_bytes()
    if len(ct1) != len(ct2):
        raise SystemExit("ct1 and ct2 lengths differ")
    xor_ct = xor_bytes(ct1, ct2)  # equals pt1 ⊕ pt2 when same noise
    save_bytes_as_png(xor_ct, w, h, XOR_CT_PNG)

    # Optional: if originals provided, show xor_plain and recovery
    xor_equal = None
    rec2_ok = None
    rec1_ok = None
    if args.img1 and args.img2:
        im1 = load_square_rgb(Path(args.img1), w)
        im2 = load_square_rgb(Path(args.img2), w)
        pt1, pt2 = im1.tobytes(), im2.tobytes()
        xor_plain = xor_bytes(pt1, pt2)
        save_bytes_as_png(xor_plain, w, h, XOR_PLAIN_PNG)
        xor_equal = (xor_ct == xor_plain)

        # Demonstrate recovery: pt2 = (ct1 ⊕ ct2) ⊕ pt1; pt1 = (ct1 ⊕ ct2) ⊕ pt2
        rec2 = xor_bytes(xor_ct, pt1)
        save_bytes_as_png(rec2, w, h, RECOVERED2_PNG)
        rec2_ok = (rec2 == pt2)
        rec1 = xor_bytes(xor_ct, pt2)
        save_bytes_as_png(rec1, w, h, RECOVERED1_PNG)
        rec1_ok = (rec1 == pt1)

    emit_json(LOGGER, {
        "module": "reuse", "mode": "img_combine",
        "metrics": {"step": "combine", "bytes": {"ct1": len(ct1), "ct2": len(ct2)},
                    "xor_equal_to_plain": bool(xor_equal) if xor_equal is not None else None,
                    "recovered2_ok": bool(rec2_ok) if rec2_ok is not None else None,
                    "recovered1_ok": bool(rec1_ok) if rec1_ok is not None else None,
                    "note": "XOR(ct1,ct2)=XOR(pt1,pt2) when same keystream; recovery works with one known plaintext."}
    })
    print(f"[ctrimg:combine] wrote {XOR_CT_PNG.name}" + (", recovery images saved" if rec2_ok is not None else ""))


def main():
    ap = argparse.ArgumentParser(description="AES-CTR image XOR demo (4-step).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_noise = sub.add_parser("noise", help="Generate AES-CTR keystream (noise) for image-sized buffer")
    p_noise.add_argument("--ref", type=str, help="Reference image to derive size (optional)")
    p_noise.add_argument("--size", type=int, default=512, help="Square size (used if no --ref)")
    p_noise.add_argument("--key-hex", type=parse_hex, default=None, help="AES key (16/24/32B)")
    p_noise.add_argument("--iv-hex", type=parse_hex, default=None, help="AES-CTR IV (16B)")
    p_noise.set_defaults(func=cmd_noise)

    p_apply1 = sub.add_parser("apply1", help="XOR noise with assets/test1.jpg -> ct1")
    p_apply1.add_argument("--img", type=str, default=str(ASSETS / "test1.jpg"))
    p_apply1.set_defaults(func=lambda a: cmd_apply(a, which=1))

    p_apply2 = sub.add_parser("apply2", help="XOR noise with assets/test2.jpg -> ct2")
    p_apply2.add_argument("--img", type=str, default=str(ASSETS / "test2.jpg"))
    p_apply2.set_defaults(func=lambda a: cmd_apply(a, which=2))

    p_combine = sub.add_parser("combine", help="XOR ct1 and ct2; optional recovery if originals given")
    p_combine.add_argument("--img1", type=str, help="Optional original 1 for validation/recovery")
    p_combine.add_argument("--img2", type=str, help="Optional original 2 for validation/recovery")
    p_combine.set_defaults(func=cmd_combine)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
