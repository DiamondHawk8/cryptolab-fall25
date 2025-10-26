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

    # QUICK-RUN + FLOW
    p.add_argument("--preset", choices=["checkerboard", "selfie-pp", "compare-pp"], default=None,
                   help="Run a preconfigured sequence (overrides some flags).")
    p.add_argument("--flow", choices=["ecb", "gcm", "both"], default="both",
                   help="Run only ECB, only GCM, or both (default).")
    p.add_argument("--save-gcm-visual", action="store_true",
                   help="Also save a GCM ciphertext visual PNG (will look like noise).")

    args = p.parse_args()

    if args.preset == "checkerboard":
        args.inp = str(repo_root / "assets" / "checkerboard_256.png")
        args.preprocess = False
        args.flow = "both"
    elif args.preset == "selfie-pp":
        # good-looking ECB demo on typical photos
        args.preprocess = True
        args.pp_mode = "rgba"
        args.pp_blur = 0.8
        args.pp_quantize = 16
        args.pp_target_width = 512
        args.flow = "ecb"
    elif args.preset == "compare-pp":
        # side-by-side metrics comparison (ECB vs GCM) on a photo
        args.preprocess = True
        args.pp_mode = "rgba"
        args.pp_blur = 0.8
        args.pp_quantize = 16
        args.pp_target_width = 512
        args.flow = "both"

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
    ecb_done = False
    if args.flow in ("ecb", "both"):
        t0 = time.perf_counter()
        ct_ecb = aes_ecb_encrypt(raw_padded, key)
        ms_ecb = (time.perf_counter() - t0) * 1000.0
        ecb_done = True

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

    # GCM encrypt (time it, store raw bin + meta)
    gcm_done = False
    if args.flow in ("gcm", "both"):
        t0 = time.perf_counter()
        ct_gcm, nonce, tag = aes_gcm_encrypt(raw_padded, key, nonce=args.nonce_hex)
        ms_gcm = (time.perf_counter() - t0) * 1000.0
        gcm_done = True

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

        # Always build a canvas-aligned slice for GCM visuals/composition
        gcm_raw_for_canvas = ct_gcm[: w * h * c]
        if len(gcm_raw_for_canvas) < w * h * c:
            gcm_raw_for_canvas = gcm_raw_for_canvas.ljust(w * h * c, b"\x00")

        if args.save_gcm_visual:
            gcm_visual = outdir / "pcb_gcm.png"
            pil_mode = "RGBA" if c == 4 else ("L" if c == 1 else "RGB")
            Image.frombytes(pil_mode, (w, h), gcm_raw_for_canvas).save(gcm_visual, "PNG")

        if args.save_gcm_visual and not args.no_side_by_side:
            if c == 4:
                gcm_img_for_comp = Image.frombytes("RGBA", (w, h), gcm_raw_for_canvas).convert("RGB")
            elif c == 1:
                gcm_img_for_comp = Image.frombytes("L", (w, h), gcm_raw_for_canvas).convert("RGB")
            else:
                gcm_img_for_comp = Image.frombytes("RGB", (w, h), gcm_raw_for_canvas)
            gcm_rgb_raw = gcm_img_for_comp.tobytes()
            try:
                compose_side_by_side(
                    str((outdir / "pcb_side_by_side_gcm.png")),
                    images=[(orig_rgb_raw, w, h), (gcm_rgb_raw, w, h)],
                    labels=["Original", "GCM"],
                )
            except Exception:
                pass

        # Metrics (GCM duplicates—should be ~0)
        gcm_identical, gcm_total, gcm_ratio = identical_block_count(ct_gcm, 16)

    # Log JSONL (stable schema)
    payload = {
        "module": "ecb",
        "mode": "attack" if ecb_done and not gcm_done else ("patched" if gcm_done and not ecb_done else "both"),
        "metrics": {
            "img": {"w": w, "h": h, "channels": c, "block_bytes": 16},
            "bytes": {"in": len(raw), "in_padded": len(raw_padded)},
            "note": "ECB leaks structure via identical 16-byte ciphertext blocks; GCM with unique nonce does not.",
        },
    }
    if ecb_done:
        payload["metrics"].update({
            "identical_blocks": identical,
            "total_blocks": total,
            "block_match_ratio": round(ratio, 6),
        })
        payload["metrics"]["bytes"]["ecb_ct"] = len(ct_ecb)
        payload["metrics"]["ms"] = {"ecb_encrypt": round(ms_ecb, 3)}
    if gcm_done:
        payload["metrics"]["bytes"].update({"gcm_ct": len(ct_gcm), "gcm_tag": len(tag)})
        payload["metrics"].update({
            "gcm_identical_blocks": gcm_identical,
            "gcm_total_blocks": gcm_total,
            "gcm_block_match_ratio": round(gcm_ratio, 6),
            "gcm": {"nonce_hex": nonce.hex(), "tag_len": len(tag)},
        })
        payload["metrics"].setdefault("ms", {})
        payload["metrics"]["ms"].update({"gcm_encrypt": round(ms_gcm, 3)})

    emit_json(logger, payload)

    # Console summary fo debug
    print(
        f"[ecb_demo] wrote:\n"
        f"  - {pcb_original}\n"
        f"  - {(outdir / 'pcb_ecb.png') if ecb_done else '(ECB skipped)'}\n"
        f"  - {(outdir / 'pcb_gcm.bin') if gcm_done else '(GCM skipped)'}"
        f" (+ {(outdir / 'pcb_gcm.meta.json') if gcm_done else 'n/a'})\n"
        f"  - {(outdir / 'pcb_side_by_side.png') if (ecb_done and (outdir / 'pcb_side_by_side.png').exists()) else '(no side-by-side requested or ECB skipped)'}\n"
        + (f"[compare] block_match_ratio: ECB={ratio:.6f} vs GCM={gcm_ratio:.6f} "
           f"(identical blocks: {identical}/{total} vs {gcm_identical}/{gcm_total})\n" if (ecb_done and gcm_done) else "")
        + (f"[ecb_demo] identical_blocks={identical} / total_blocks={total} (ratio={ratio:.4f})  |  " if ecb_done else "")
        + (f"ms: ecb={ms_ecb:.2f} " if ecb_done else "")
        + (f"gcm={ms_gcm:.2f}" if gcm_done else "")
    )




if __name__ == "__main__":
    main()
