from __future__ import annotations
import argparse
import sys
import subprocess
import shlex
from pathlib import Path

from src.cryptolab.logging_utils import ensure_logger

REPO = Path(__file__).resolve().parent
PY = sys.executable

ECB_DEMO = REPO / "src" / "cryptolab" / "ecb_demo.py"
REUSE_DEMO = REPO / "src" / "cryptolab" / "reuse_demo.py"
DOWNGRADE_DEMO = REPO / "src" / "cryptolab" / "downgrade_demo.py"  # TODO

DEFAULT_OUT = REPO / "outputs"
CHECKERBOARD = REPO / "assets" / "checkerboard_256.png"

CTRIMG_DEMO = REPO / "src" / "cryptolab" / "ctr_image_demo.py"

REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / "assets"
LOGS = REPO / "logs"
LOGS.mkdir(parents=True, exist_ok=True)
LOGGER = ensure_logger(str(LOGS), "metrics.jsonl", level="INFO")

# Hardcoded outputs
OUTPUTS = REPO / "outputs"
OUTPUTS.mkdir(parents=True, exist_ok=True)
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

def run(cmd: list[str], dry: bool = False) -> int:
    print("->", " ".join(shlex.quote(c) for c in cmd))
    if dry:
        return 0
    return subprocess.run(cmd).returncode


# ECB ROUTES
def ecb_pp(photo: Path, out: Path, dry: bool) -> int:
    return run([
        str(PY), str(ECB_DEMO),
        "--in", str(photo),
        "--out", str(out),
        "--preprocess",
        "--pp-mode", "rgba",
        "--pp-blur", "0.8",
        "--pp-quantize", "16",
        "--pp-target-width", "512",
        "--flow", "ecb",
    ], dry=dry)


def ecb_gcm(photo: Path, out: Path, save_gcm_visual: bool, dry: bool) -> int:
    cmd = [
        str(PY), str(ECB_DEMO),
        "--in", str(photo),
        "--out", str(out),
        "--flow", "gcm",
        "--save-gcm-visual"
    ]
    if save_gcm_visual:
        cmd.append("--save-gcm-visual")
    return run(cmd, dry=dry)


def ecb_checkerboard(out: Path, save_gcm_visual: bool, dry: bool) -> int:
    cmd = [
        str(PY), str(ECB_DEMO),
        "--in", str(CHECKERBOARD),
        "--out", str(out),
        "--preset", "checkerboard",  # internally sets flow=both
    ]
    if save_gcm_visual:
        cmd.append("--save-gcm-visual")
    return run(cmd, dry=dry)


def ecb_nopp(photo: Path, out: Path, dry: bool) -> int:
    return run([
        str(PY), str(ECB_DEMO),
        "--in", str(photo),
        "--out", str(out),
        "--flow", "ecb",
    ], dry=dry)


# NONCE-REUSE ROUTES
def reuse_attack(out: Path, dry: bool, *, algo: str | None = None, key_hex: str | None = None,
                 nonce_hex: str | None = None, danger: bool = False) -> int:
    """
    Attack path: reuse nonce across two plaintexts; produce xor-of-plaintexts metric.
    :param out:
    :param dry:
    :param algo:
    :param key_hex:
    :param nonce_hex:
    :param danger:
    :return:
    """
    cmd = [
        str(PY), str(REUSE_DEMO),
        "--mode", "attack",
        "--out", str(out),
    ]
    if algo:
        cmd += ["--algo", algo]
    if key_hex:
        cmd += ["--key-hex", key_hex]
    if nonce_hex:
        cmd += ["--nonce-hex", nonce_hex]
    if danger:
        cmd += ["--danger-educational"]
    return run(cmd, dry=dry)


def reuse_patched(out: Path, dry: bool, *, algo: str | None = None, key_hex: str | None = None) -> int:
    """
    Patched path: enforce unique nonces; show clean metrics (no xor leakage).
    :param out:
    :param dry:
    :param algo:
    :param key_hex:
    :return:
    """
    cmd = [
        str(PY), str(REUSE_DEMO),
        "--mode", "patched",
        "--out", str(out),
    ]
    if algo:
        cmd += ["--algo", algo]
    if key_hex:
        cmd += ["--key-hex", key_hex]
    return run(cmd, dry=dry)


# DOWNGRADE ROUTES (TODO)
def downgrade_attack(out: Path, dry: bool) -> int:
    """
    Attack path: force weaker cipher/params via MITM; expect blocked in patched run.
    """
    return run([
        str(PY), str(DOWNGRADE_DEMO),
        "--mode", "attack",
        "--out", str(out),
    ], dry=dry)


def downgrade_patched(out: Path, dry: bool) -> int:
    """
    Patched path: server/client reject downgrade; metrics log the block.
    """
    return run([
        str(PY), str(DOWNGRADE_DEMO),
        "--mode", "patched",
        "--out", str(out),
    ], dry=dry)


# CTR IMAGE ROUTES
def ctrimg_noise(out: Path, dry: bool, ref: Path | None, size: int | None,
                 key_hex: str | None, iv_hex: str | None) -> int:
    cmd = [str(PY), str(CTRIMG_DEMO), "noise"]
    if ref:     cmd += ["--ref", str(ref)]
    if size:    cmd += ["--size", str(size)]
    if key_hex: cmd += ["--key-hex", key_hex]
    if iv_hex:  cmd += ["--iv-hex", iv_hex]
    return run(cmd, dry=dry)




def ctrimg_apply1(out: Path, dry: bool, img: Path | None) -> int:
    cmd = [str(PY), str(CTRIMG_DEMO), "apply1"]
    if img: cmd += ["--img", str(img)]
    return run(cmd, dry=dry)

def ctrimg_apply2(out: Path, dry: bool, img: Path | None) -> int:
    cmd = [str(PY), str(CTRIMG_DEMO), "apply2"]
    if img: cmd += ["--img", str(img)]
    return run(cmd, dry=dry)


def ctrimg_combine(out: Path, dry: bool, img1: Path | None, img2: Path | None) -> int:
    cmd = [str(PY), str(CTRIMG_DEMO), "combine"]
    if img1: cmd += ["--img1", str(img1)]
    if img2: cmd += ["--img2", str(img2)]
    return run(cmd, dry=dry)


def main():
    DEFAULT_OUT.mkdir(parents=True, exist_ok=True)

    ap = argparse.ArgumentParser(description="CryptoLab Orchestrator — route all demos via simple commands.")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT), help="Output directory (default: ./outputs)")
    ap.add_argument("--dry-run", action="store_true", help="Print the command without executing.")
    sub = ap.add_subparsers(dest="demo", required=True)

    # ecb subcommands
    ecb = sub.add_parser("ecb", help="ECB leak presets")
    ecb_sub = ecb.add_subparsers(dest="action", required=True)

    p_ecb_pp = ecb_sub.add_parser("pp", help="ECB with preprocessing + side-by-side (use --photo)")
    p_ecb_pp.add_argument("--photo", required=True, help="Path to image")

    p_ecb_gcm = ecb_sub.add_parser("gcm", help="Secure GCM baseline on the same image (no preprocess)")
    p_ecb_gcm.add_argument("--photo", required=True, help="Path to image")
    p_ecb_gcm.add_argument("--save-gcm-visual", action="store_true", help="Also save a GCM noise visual")

    p_ecb_checker = ecb_sub.add_parser("checkerboard", help="Supplement: checkerboard ECB (no preprocess)")
    p_ecb_checker.add_argument("--save-gcm-visual", action="store_true", help="Also save a GCM noise visual")

    p_ecb_nopp = ecb_sub.add_parser("nopp", help="Supplement: your image, ECB only, no preprocess")
    p_ecb_nopp.add_argument("--photo", required=True, help="Path to image")

    # reuse subcommands (attack/patched)
    reuse = sub.add_parser("reuse", help="Nonce reuse demo presets")
    reuse_sub = reuse.add_subparsers(dest="action", required=True)

    ctrimg = sub.add_parser("ctrimg", help="AES-CTR image XOR 4-step demo")
    ctrimg_sub = ctrimg.add_subparsers(dest="action", required=True)

    p_noise = ctrimg_sub.add_parser("noise", help="Generate keystream (noise)")
    p_noise.add_argument("--ref", type=str, help="Reference image (derive size)")
    p_noise.add_argument("--size", type=int, help="Square size if no --ref")
    p_noise.add_argument("--key-hex", help="AES key (16/24/32B)")
    p_noise.add_argument("--iv-hex", help="AES-CTR IV (16B)")

    p_apply1 = ctrimg_sub.add_parser("apply1", help="XOR noise with assets/test1.jpg")
    p_apply1.add_argument("--img", type=str, default=str(ASSETS / "test1.jpg"))

    p_apply2 = ctrimg_sub.add_parser("apply2", help="XOR noise with assets/test2.jpg")
    p_apply2.add_argument("--img", type=str, default=str(ASSETS / "test2.jpg"))

    p_combine = ctrimg_sub.add_parser("combine", help="XOR ct1 and ct2; optional recovery if originals given")
    p_combine.add_argument("--img1", type=str)
    p_combine.add_argument("--img2", type=str)

    def add_reuse_args(p):
        p.add_argument("--algo", choices=["aesgcm", "chacha20"], default="aesgcm",
                       help="AEAD algorithm (default: aesgcm)")
        p.add_argument("--key-hex", help="Key in hex (32 bytes recommended)")
        p.add_argument("--nonce-hex", help="12-byte nonce in hex (used only in attack)")
        p.add_argument("--danger-educational", action="store_true",
                       help="Required to run attack (enables nonce reuse)")

    p_reuse_attack = reuse_sub.add_parser("attack", help="Nonce reuse attack (same nonce across two msgs)")
    add_reuse_args(p_reuse_attack)

    p_reuse_patched = reuse_sub.add_parser("patched", help="Nonce reuse patched (unique nonces)")
    add_reuse_args(p_reuse_patched)

    # downgrade subcommands (attack/patched)
    dgd = sub.add_parser("downgrade", help="Downgrade/rollback demo presets")
    dgd_sub = dgd.add_subparsers(dest="action", required=True)
    dgd_sub.add_parser("attack", help="Force weaker params (attack)")
    dgd_sub.add_parser("patched", help="Reject downgrade (patched)")

    args = ap.parse_args()
    out = Path(args.out);
    out.mkdir(parents=True, exist_ok=True)

    # dispatch
    if args.demo == "ecb":
        if args.action == "pp":
            rc = ecb_pp(photo=Path(args.photo).resolve(), out=out, dry=args.dry_run)
        elif args.action == "gcm":
            rc = ecb_gcm(photo=Path(args.photo).resolve(), out=out,
                         save_gcm_visual=args.save_gcm_visual, dry=args.dry_run)
        elif args.action == "checkerboard":
            rc = ecb_checkerboard(out=out, save_gcm_visual=args.save_gcm_visual, dry=args.dry_run)
        else:  # nopp
            rc = ecb_nopp(photo=Path(args.photo).resolve(), out=out, dry=args.dry_run)

    elif args.demo == "reuse":
        if args.action == "attack":
            rc = reuse_attack(
                out=out, dry=args.dry_run,
                algo=getattr(args, "algo", None),
                key_hex=getattr(args, "key_hex", None),
                nonce_hex=getattr(args, "nonce_hex", None),
                danger=getattr(args, "danger_educational", False),
            )
        else:
            rc = reuse_patched(
                out=out, dry=args.dry_run,
                algo=getattr(args, "algo", None),
                key_hex=getattr(args, "key_hex", None),
            )
    elif args.demo == "ctrimg":
        if args.action == "noise":
            rc = ctrimg_noise(out=out, dry=args.dry_run,
                              ref=Path(args.ref).resolve() if getattr(args, "ref", None) else None,
                              size=getattr(args, "size", None),
                              key_hex=getattr(args, "key_hex", None),
                              iv_hex=getattr(args, "iv_hex", None))
        elif args.action == "apply1":
            rc = ctrimg_apply1(out=out, dry=args.dry_run,
                               img=Path(args.img).resolve() if getattr(args, "img", None) else None)
        elif args.action == "apply2":
            rc = ctrimg_apply2(out=out, dry=args.dry_run,
                               img=Path(args.img).resolve() if getattr(args, "img", None) else None)
        else:
            rc = ctrimg_combine(out=out, dry=args.dry_run,
                                img1=Path(args.img1).resolve() if getattr(args, "img1", None) else None,
                                img2=Path(args.img2).resolve() if getattr(args, "img2", None) else None)


    else:  # downgrade
        if args.action == "attack":
            rc = downgrade_attack(out=out, dry=args.dry_run)
        else:
            rc = downgrade_patched(out=out, dry=args.dry_run)

    sys.exit(rc)


if __name__ == "__main__":
    main()
