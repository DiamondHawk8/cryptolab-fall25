from __future__ import annotations
import argparse
import sys
import subprocess
import shlex
from pathlib import Path

REPO = Path(__file__).resolve().parent
PY = sys.executable

ECB_DEMO = REPO / "src" / "cryptolab" / "ecb_demo.py"
REUSE_DEMO = REPO / "src" / "cryptolab" / "reuse_demo.py"  # TODO
DOWNGRADE_DEMO = REPO / "src" / "cryptolab" / "downgrade_demo.py"  # TODO

DEFAULT_OUT = REPO / "outputs"
CHECKERBOARD = REPO / "assets" / "checkerboard_256.png"


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


# NONCE-REUSE ROUTES (TODO)
def reuse_attack(out: Path, dry: bool) -> int:
    """
    Attack path: reuse nonce across two plaintexts; produce xor-of-plaintexts metric.
    """
    return run([
        str(PY), str(REUSE_DEMO),
        "--mode", "attack",
        "--out", str(out),
    ], dry=dry)

def reuse_patched(out: Path, dry: bool) -> int:
    """
    Patched path: enforce unique nonces; show clean metrics (no xor leakage).
    """
    return run([
        str(PY), str(REUSE_DEMO),
        "--mode", "patched",
        "--out", str(out),
    ], dry=dry)


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
    reuse_sub.add_parser("attack", help="Nonce reuse attack (same nonce across two msgs)")
    reuse_sub.add_parser("patched", help="Nonce reuse patched (unique nonces)")

    # downgrade subcommands (attack/patched)
    dgd = sub.add_parser("downgrade", help="Downgrade/rollback demo presets")
    dgd_sub = dgd.add_subparsers(dest="action", required=True)
    dgd_sub.add_parser("attack", help="Force weaker params (attack)")
    dgd_sub.add_parser("patched", help="Reject downgrade (patched)")

    args = ap.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

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
            rc = reuse_attack(out=out, dry=args.dry_run)
        else:
            rc = reuse_patched(out=out, dry=args.dry_run)

    else:  # downgrade
        if args.action == "attack":
            rc = downgrade_attack(out=out, dry=args.dry_run)
        else:
            rc = downgrade_patched(out=out, dry=args.dry_run)

    sys.exit(rc)


if __name__ == "__main__":
    main()