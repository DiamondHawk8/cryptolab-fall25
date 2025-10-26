from __future__ import annotations
import argparse
import binascii
import json
import time
from pathlib import Path
from PIL import Image, ImageFilter

from image_utils import load_rgb_bytes, save_rgb_bytes, compose_side_by_side
from crypto_utils import pkcs7_pad, aes_ecb_encrypt, aes_gcm_encrypt
from metrics import identical_block_count
from logging_utils import ensure_logger, emit_json


def parse_hex(s: str) -> bytes:

    s = s.strip().lower().replace("0x", "").replace(" ", "")

    if len(s) % 2 != 0:
        s = "0" + s
    try:
        return binascii.unhexlify(s)
    except binascii.Error as e:
        raise argparse.ArgumentTypeError(f"Invalid hex: {e}")


def main():
    repo_root = Path(__file__).resolve().parents[2]
    default_in = repo_root / "assets" / "checkerboard_256.png"
    default_out = repo_root / "outputs"
    logs_dir = repo_root / "logs"

    p = argparse.ArgumentParser(
        description="ECB leakage demo: encrypt an image with AES-ECB and AES-GCM, output visuals and metrics."
    )

    p.add_argument("--in", dest="inp", type=str, default=str(default_in), help="Input image (PNG/JPG).")
    p.add_argument("--out", dest="outdir", type=str, default=str(default_out), help="Output directory.")
    p.add_argument("--key-hex", type=parse_hex, default=None, help="AES key in hex (16/24/32 bytes).")
    p.add_argument("--nonce-hex", type=parse_hex, default=None, help="12-byte GCM nonce in hex (optional).")
    p.add_argument("--no-side-by-side", action="store_true", help="Skip composing side-by-side PNG.")

    # Preprocessing args to get more entropic images to show the effect
    p.add_argument("--preprocess", action="store_true",
                   help="Enable image preprocessing to amplify ECB leakage (blur/quantize/format/resize).")
    p.add_argument("--pp-mode", choices=["rgb", "rgba", "gray"], default="rgba",
                   help="Pixel format used when --preprocess is enabled (affects block alignment).")
    p.add_argument("--pp-quantize", type=int, default=16,
                   help="Palette size when --preprocess is on (0 to skip).")
    p.add_argument("--pp-blur", type=float, default=0.8,
                   help="Gaussian blur radius when --preprocess is on (0 to skip).")
    p.add_argument("--pp-target-width", type=int, default=512,
                   help="Resize shorter side to this width when --preprocess is on (0 to skip).")

    args = p.parse_args()

    if args.preprocess:
        img = Image.open(args.inp)

        # Optional uniform resize (shorter side -> pp-target-width)
        if args.pp_target_width and args.pp_target_width > 0:
            w0, h0 = img.size
            if min(w0, h0) != args.pp_target_width:
                if w0 < h0:
                    img = img.resize((args.pp_target_width, int(h0 * args.pp_target_width / w0)), Image.BICUBIC)
                else:
                    img = img.resize((int(w0 * args.pp_target_width / h0), args.pp_target_width), Image.BICUBIC)

        # Optional blur (smooth micro-variations)
        if args.pp_blur and args.pp_blur > 0:
            img = img.filter(ImageFilter.GaussianBlur(radius=args.pp_blur))

        # Optional quantize (boosts flat regions)
        if args.pp_quantize and args.pp_quantize > 0:
            img = img.convert("P", palette=Image.ADAPTIVE, colors=max(2, args.pp_quantize))

        # Select pixel format
        if args.pp_mode == "rgba":
            img = img.convert("RGBA")
            c = 4
        elif args.pp_mode == "gray":
            img = img.convert("L")
            c = 1
        else:
            img = img.convert("RGB")
            c = 3

        # Align width to AES block boundary in pixels
        block_pixels = 16 // c
        if block_pixels > 0:
            w_curr, h_curr = img.size
            if (w_curr % block_pixels) != 0:
                new_w = max(block_pixels, (w_curr // block_pixels) * block_pixels)
                img = img.crop((0, 0, new_w, h_curr))

        # Replace raw, w, h, c with preprocessed values
        w, h = img.size
        raw = img.tobytes()
    else:
        # Load original image as raw RGB
        raw, w, h, c = load_rgb_bytes(args.inp)


    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Build a presentation "original" = pre-preprocess RGB resized to (w,h)
    orig_img_disp = Image.open(args.inp).convert("RGB")
    if orig_img_disp.size != (w, h):
        orig_img_disp = orig_img_disp.resize((w, h), Image.BICUBIC)
    orig_rgb_raw = orig_img_disp.tobytes()

    # Save the presentation original
    pcb_original = outdir / "pcb_original.png"
    orig_img_disp.save(pcb_original, "PNG")

    logger = ensure_logger(str(logs_dir), "metrics.jsonl", level="INFO")

    # Pad raw for block cipher operations (generic for any image)
    raw_padded = pkcs7_pad(raw, 16)

    # ------- Keys/nonces
    key = args.key_hex if args.key_hex is not None else (b"\x00" * 16)  # deterministic default
    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 16/24/32 bytes (128/192/256-bit)")

    # ECB encrypt (time it as well)
    t0 = time.perf_counter()
    ct_ecb = aes_ecb_encrypt(raw_padded, key)
    ms_ecb = (time.perf_counter() - t0) * 1000.0

    # GCM encrypt (time it, store raw bin + meta)
    t0 = time.perf_counter()
    ct_gcm, nonce, tag = aes_gcm_encrypt(raw_padded, key, nonce=args.nonce_hex)
    ms_gcm = (time.perf_counter() - t0) * 1000.0

    gcm_bin = outdir / "pcb_gcm.bin"
    gcm_meta = outdir / "pcb_gcm.meta.json"

    with open(gcm_bin, "wb") as f:
        f.write(ct_gcm + tag)
    with open(gcm_meta, "w", encoding="utf-8") as f:
        json.dump(
            {
                "nonce_hex": nonce.hex(),
                "tag_len": len(tag),
                "ciphertext_len": len(ct_gcm),
                "note": "pcb_gcm.bin stores ciphertext||tag (tag is last 16 bytes).",
            },
            f,
            indent=2,
        )

    # Visualize ECB ciphertext as an image (crop to original canvas size)
    ecb_visual = outdir / "pcb_ecb.png"

    bpp = c
    ecb_raw_for_canvas = ct_ecb[: w * h * bpp]
    if len(ecb_raw_for_canvas) < w * h * bpp:
        ecb_raw_for_canvas = ecb_raw_for_canvas.ljust(w * h * bpp, b"\x00")

    pil_mode = "RGBA" if c == 4 else ("L" if c == 1 else "RGB")
    Image.frombytes(pil_mode, (w, h), ecb_raw_for_canvas).save(ecb_visual, "PNG")

    if c == 4:
        ecb_img_for_comp = Image.frombytes("RGBA", (w, h), ecb_raw_for_canvas).convert("RGB")
    elif c == 1:
        ecb_img_for_comp = Image.frombytes("L", (w, h), ecb_raw_for_canvas).convert("RGB")
    else:
        ecb_img_for_comp = Image.frombytes("RGB", (w, h), ecb_raw_for_canvas)
    ecb_rgb_raw = ecb_img_for_comp.tobytes()

    # BEGIN C: side-by-side composition using pre-preprocess original (orig_rgb_raw)
    side_by_side = outdir / "pcb_side_by_side.png"
    if not args.no_side_by_side:
        try:
            compose_side_by_side(
                str(side_by_side),
                images=[(orig_rgb_raw, w, h), (ecb_rgb_raw, w, h)],
                labels=["Original", "ECB"],
            )
        except Exception:
            pass

    # Metrics on ECB (duplicates)
    identical, total, ratio = identical_block_count(ct_ecb, 16)

    # Log JSONL (stable schema)
    payload = {
        "module": "ecb",
        "mode": "attack",  # ECB is the 'attack' variant; GCM is the secure baseline
        "metrics": {
            "img": {"w": w, "h": h, "channels": c, "block_bytes": 16},
            "identical_blocks": identical,
            "total_blocks": total,
            "block_match_ratio": round(ratio, 6),
            "bytes": {
                "in": len(raw),
                "in_padded": len(raw_padded),
                "ecb_ct": len(ct_ecb),
                "gcm_ct": len(ct_gcm),
                "gcm_tag": len(tag),
            },
            "ms": {"ecb_encrypt": round(ms_ecb, 3), "gcm_encrypt": round(ms_gcm, 3)},
            "gcm": {"nonce_hex": nonce.hex(), "tag_len": len(tag)},
            "note": "ECB leaks structure via identical 16-byte ciphertext blocks; GCM with unique nonce does not.",
        },
    }
    emit_json(logger, payload)

    # Console summary fo debug
    print(
        f"[ecb_demo] wrote:\n"
        f"  - {pcb_original}\n"
        f"  - {ecb_visual}\n"
        f"  - {gcm_bin} (+ {gcm_meta})\n"
        f"  - {side_by_side if side_by_side.exists() else '(no side-by-side requested)'}\n"
        f"[ecb_demo] identical_blocks={identical} / total_blocks={total} "
        f"(ratio={ratio:.4f})  |  ms: ecb={ms_ecb:.2f}, gcm={ms_gcm:.2f}"
    )


if __name__ == "__main__":
    main()
