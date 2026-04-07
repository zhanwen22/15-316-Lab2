from __future__ import annotations

import argparse
import re
import statistics
import subprocess
import sys
import time

_SUCCESS = re.compile(r"^success\s+(-?\d+)\s*$", re.MULTILINE)
_FAILURE = re.compile(r"^failure\s+(-?\d+)\s*$", re.MULTILINE)
_INSECURE = re.compile(r"^insecure\s*$", re.MULTILINE)
_ABORT = re.compile(r"^abort\s*$", re.MULTILINE)
_ERROR = re.compile(r"^error\s*$", re.MULTILINE)
_SIMPLE = re.compile(r"^(insecure|error|abort)\s*$", re.MULTILINE)

MAX_U62 = (1 << 62) - 1


# -------------------------------
# RUN SERVER
# -------------------------------
def run_serve(serve: str, userid: str, c0: str, x: int, timeout: float):
    cmd = f"{serve} {userid} {c0} {x}"
    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return (proc.stdout or "").strip(), proc.returncode


# -------------------------------
# NEW: ORACLE VALIDATION
# -------------------------------
def classify_oracle(serve, userid, c0, timeout):
    try:
        out, rc = run_serve(serve, userid, c0, 0, timeout)
    except subprocess.TimeoutExpired:
        return False, "timeout"

    if _INSECURE.search(out):
        return False, "rejected as insecure"
    if _ERROR.search(out):
        return False, "server error"

    return True, out


# -------------------------------
# SWEEP (UNCHANGED)
# -------------------------------
def cmd_sweep(args):
    serve = f"~mfredrik/bin/c0_serve{args.server}"

    for x in range(args.start, args.stop, args.step):
        try:
            out, rc = run_serve(serve, args.userid, args.c0file, x, args.timeout)
        except subprocess.TimeoutExpired:
            continue

        if _INSECURE.search(out):
            print("❌ program rejected as insecure", file=sys.stderr)
            return 4

        if _SUCCESS.search(out):
            val = int(_SUCCESS.search(out).group(1))
            print(val)
            return 0

        if args.verbose:
            print(f"{x} -> {out}", file=sys.stderr)

    print("no success found")
    return 1


# -------------------------------
# BINARY SEARCH (SAFE VERSION)
# -------------------------------
def cmd_binary(args):
    serve = f"~mfredrik/bin/c0_serve{args.server}"

    # choose oracle
    if args.oracle == "termination":
        compare = "./examples/compare_via_termination.c0"
    elif args.oracle == "timing":
        compare = "./examples/compare_timing_branches.c0"
    else:
        compare = "./examples/compare_secret_to_input.c0"

    # 🔥 NEW: validate oracle FIRST
    ok, msg = classify_oracle(serve, args.userid, compare, args.timeout)

    if not ok:
        print(
            f"\n❌ ORACLE REJECTED: {compare}\n"
            f"Reason: {msg}\n\n"
            "Lecture interpretation:\n"
            "  - implicit flows blocked\n"
            "  - OR termination-sensitive policy\n"
            "  - OR timing-sensitive policy\n\n"
            "👉 This is NOT a Python bug.\n"
            "👉 Your .c0 program is being rejected.\n",
            file=sys.stderr,
        )
        return 4

    lo, hi = 0, MAX_U62

    while lo < hi:
        mid = (lo + hi + 1) // 2

        try:
            out, rc = run_serve(serve, args.userid, compare, mid, args.timeout)
        except subprocess.TimeoutExpired:
            print("timeout during binary search", file=sys.stderr)
            return 1

        if _INSECURE.search(out):
            print("❌ oracle became insecure mid-run", file=sys.stderr)
            return 4

        m = _FAILURE.search(out)
        if not m:
            print(f"unexpected output: {out}", file=sys.stderr)
            return 1

        bit = int(m.group(1))

        if args.verbose:
            print(f"mid={mid} -> {bit}", file=sys.stderr)

        if bit == 1:
            hi = mid - 1
        else:
            lo = mid

    print(lo)
    return 0


# -------------------------------
# ARGPARSE
# -------------------------------
def build_parser():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("sweep")
    ps.add_argument("server", type=int)
    ps.add_argument("c0file")
    ps.add_argument("--userid", default="wennaz")
    ps.add_argument("--start", type=int, default=0)
    ps.add_argument("--stop", type=int, required=True)
    ps.add_argument("--step", type=int, default=1)
    ps.add_argument("--timeout", type=float, default=30)
    ps.add_argument("-v", "--verbose", action="store_true")
    ps.set_defaults(func=cmd_sweep)

    pb = sub.add_parser("binary")
    pb.add_argument("server", type=int)
    pb.add_argument("--userid", default="wennaz")
    pb.add_argument(
        "--oracle",
        choices=("implicit", "termination", "timing"),
        default="implicit",
    )
    pb.add_argument("--timeout", type=float, default=30)
    pb.add_argument("-v", "--verbose", action="store_true")
    pb.set_defaults(func=cmd_binary)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())