#!/usr/bin/env python3
"""
c0_serve helpers (Andrew only).

  sweep  — try many inputs until success (needs return input or similar in range).
  binary — binary search + probe:
    --oracle implicit      failure 0/1; weak IFC only.
    --oracle termination   hang vs finish when implicit is insecure.
    --oracle timing        long vs short finite loops; wall-clock median (noisy;
                           needs --timeout large enough, e.g. 90).

recover_binary.py tries implicit → termination → timing automatically unless you
pass --oracle.
"""

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


def run_serve(serve: str, userid: str, c0: str, x: int, timeout: float) -> tuple[str, int | None]:
    cmd = f"{serve} {userid} {c0} {x}"
    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return (proc.stdout or "").strip(), proc.returncode


def cmd_sweep(args: argparse.Namespace) -> int:
    serve = f"~mfredrik/bin/c0_serve{args.server}"
    tried = 0
    for x in range(args.start, args.stop, args.step):
        tried += 1
        if args.progress_every and tried % args.progress_every == 0:
            print(f"... tried up to input={x}", file=sys.stderr)

        try:
            out, rc = run_serve(serve, args.userid, args.c0file, x, args.timeout)
        except subprocess.TimeoutExpired:
            if args.verbose:
                print(f"input={x} TIMEOUT", file=sys.stderr)
            continue

        if _INSECURE.search(out):
            print("insecure: this .c0 is rejected on this server.", file=sys.stderr)
            return 4
        if _ABORT.search(out):
            print("abort: fix your C0 program.", file=sys.stderr)
            return 3
        if _ERROR.search(out):
            print("error: check path, format, and input.", file=sys.stderr)
            return 1

        m = _SUCCESS.search(out)
        if m:
            secret = int(m.group(1))
            print(secret)
            if args.save is not None:
                with open(args.save, "w", encoding="utf-8") as f:
                    f.write(f"{secret}\n")
            return 0

        if args.verbose:
            print(f"input={x} rc={rc} stdout={out!r}", file=sys.stderr)

    print("No success in range; widen --stop or use a different .c0.", file=sys.stderr)
    return 1


def _binary_compare_path(args: argparse.Namespace) -> str:
    if args.compare is not None:
        return args.compare
    if args.oracle == "termination":
        return "./examples/compare_via_termination.c0"
    if args.oracle == "timing":
        return "./examples/compare_timing_branches.c0"
    return "./examples/compare_secret_to_input.c0"


def cmd_binary_timing(args: argparse.Namespace) -> int:
    serve = f"~mfredrik/bin/c0_serve{args.server}"
    compare = _binary_compare_path(args)
    timeout = args.timeout
    n = args.timing_samples

    def measure(inp: int) -> tuple[float | None, str, int | None]:
        times: list[float] = []
        last_out, last_rc = "", 0
        for _ in range(n):
            t0 = time.perf_counter()
            try:
                out, rc = run_serve(serve, args.userid, compare, inp, timeout)
            except subprocess.TimeoutExpired:
                return None, "timeout", None
            elapsed = time.perf_counter() - t0
            times.append(elapsed)
            last_out, last_rc = out, rc
            if _SIMPLE.search(out):
                return None, out, rc
            if _SUCCESS.search(out):
                return None, f"unexpected success during timing query: {out}", rc
            if not _FAILURE.search(out):
                return None, out, rc
        return statistics.median(times), last_out, last_rc

    fast_m, out0, rc0 = measure(0)
    if fast_m is None:
        print(f"timing calibrate input=0 failed: {out0!r} rc={rc0}", file=sys.stderr)
        return 4 if "insecure" in out0 else 1

    slow_m, out1, rc1 = measure(MAX_U62)
    if slow_m is None:
        print(f"timing calibrate input=max failed: {out1!r} rc={rc1}", file=sys.stderr)
        return 4 if "insecure" in out1 else 1

    if slow_m <= fast_m * 1.02:
        print(
            "timing calibration: slow branch not slower than fast; "
            "increase loop counts in compare_timing_branches.c0 or raise --timeout",
            file=sys.stderr,
        )
        return 1

    thresh = (fast_m + slow_m) / 2
    if args.verbose:
        print(
            f"timing cal: fast( input=0) ~{fast_m:.4f}s  "
            f"slow(input=max) ~{slow_m:.4f}s  thresh ~{thresh:.4f}s",
            file=sys.stderr,
        )

    lo, hi = 0, MAX_U62
    while lo < hi:
        mid = (lo + hi + 1) // 2
        med, outm, rcm = measure(mid)
        if med is None:
            print(f"timing query mid={mid} failed: {outm!r} rc={rcm}", file=sys.stderr)
            return 4 if "insecure" in outm else 1
        bit = 1 if med > thresh else 0
        if args.verbose:
            print(f"mid={mid} med_time={med:.4f}s -> treat as secret < mid == {bit}", file=sys.stderr)
        if bit == 1:
            hi = mid - 1
        else:
            lo = mid

    secret = lo
    if args.verbose:
        print(f"narrowed to secret={secret}, verifying with probe...", file=sys.stderr)

    try:
        out, rc = run_serve(serve, args.userid, args.probe, secret, args.timeout)
    except subprocess.TimeoutExpired:
        print("probe timed out", file=sys.stderr)
        return 1
    if _SUCCESS.search(out):
        print(secret)
        if args.save is not None:
            with open(args.save, "w", encoding="utf-8") as f:
                f.write(f"{secret}\n")
        return 0

    print(f"probe did not succeed: {out!r} rc={rc}", file=sys.stderr)
    return 1


def cmd_binary(args: argparse.Namespace) -> int:
    if args.oracle == "timing":
        return cmd_binary_timing(args)
    serve = f"~mfredrik/bin/c0_serve{args.server}"
    compare = _binary_compare_path(args)
    query_timeout = (
        args.oracle_timeout if args.oracle == "termination" else args.timeout
    )

    lo = 0
    hi = MAX_U62
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            out, rc = run_serve(serve, args.userid, compare, mid, query_timeout)
        except subprocess.TimeoutExpired:
            if args.oracle != "termination":
                print(f"compare query timeout at mid={mid}", file=sys.stderr)
                return 1
            bit = 1
            if args.verbose:
                print(f"mid={mid} TIMEOUT -> secret < mid", file=sys.stderr)
        else:
            if _SIMPLE.search(out):
                print(f"oracle query failed: {out!r} rc={rc}", file=sys.stderr)
                return 4 if "insecure" in out else 1
            sm = _SUCCESS.search(out)
            if sm:
                lo = hi = int(sm.group(1))
                if args.verbose:
                    print(f"mid={mid} success {lo} (early)", file=sys.stderr)
                break
            if args.oracle == "termination":
                bit = 0
                if args.verbose:
                    print(f"mid={mid} finished -> secret >= mid ({out!r})", file=sys.stderr)
            else:
                m = _FAILURE.search(out)
                if not m:
                    print(f"could not parse (expected failure 0|1): {out!r} rc={rc}", file=sys.stderr)
                    return 1
                bit = int(m.group(1))
                if args.verbose:
                    print(f"mid={mid} -> return {bit} ({out})", file=sys.stderr)
        if bit == 1:
            hi = mid - 1
        else:
            lo = mid

    secret = lo
    if args.verbose:
        print(f"narrowed to secret={secret}, verifying with probe...", file=sys.stderr)

    try:
        out, rc = run_serve(serve, args.userid, args.probe, secret, args.timeout)
    except subprocess.TimeoutExpired:
        print("probe timed out", file=sys.stderr)
        return 1
    if _SUCCESS.search(out):
        print(secret)
        if args.save is not None:
            with open(args.save, "w", encoding="utf-8") as f:
                f.write(f"{secret}\n")
        return 0

    print(f"probe did not succeed: {out!r} rc={rc}", file=sys.stderr)
    print("Try a different --compare, or signed/unsigned mismatch.", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Find c0_serve secrets (sweep or binary search).")
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("sweep", help="Linear search over input (return input style)")
    ps.add_argument("server", type=int, choices=range(1, 6))
    ps.add_argument("c0file", help="Path to .c0")
    ps.add_argument("--userid", default="wennaz")
    ps.add_argument("--start", type=int, default=0)
    ps.add_argument("--stop", type=int, required=True)
    ps.add_argument("--step", type=int, default=1)
    ps.add_argument("--timeout", type=float, default=30.0)
    ps.add_argument("--save", metavar="FILE", default=None)
    ps.add_argument("-v", "--verbose", action="store_true")
    ps.add_argument("--progress-every", type=int, metavar="N", default=0)
    ps.set_defaults(func=cmd_sweep)

    pb = sub.add_parser(
        "binary",
        help="Binary search with compare .c0 + probe (same idea as server 1)",
    )
    pb.add_argument("server", type=int, choices=range(1, 6))
    pb.add_argument("--userid", default="wennaz")
    pb.add_argument(
        "--oracle",
        choices=("implicit", "termination", "timing"),
        default="implicit",
        help="How each query leaks secret vs input (see module docstring)",
    )
    pb.add_argument(
        "--compare",
        default=None,
        help="Override oracle .c0 (default depends on --oracle)",
    )
    pb.add_argument(
        "--oracle-timeout",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Subprocess timeout per query for --oracle termination (only)",
    )
    pb.add_argument("--probe", default="./examples/probe.c0")
    pb.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Subprocess timeout per query and for probe (use ~90+ for --oracle timing)",
    )
    pb.add_argument(
        "--timing-samples",
        type=int,
        default=7,
        metavar="N",
        help="Median of N wall-clock samples per timing query (only --oracle timing)",
    )
    pb.add_argument("--save", metavar="FILE", default=None)
    pb.add_argument("-v", "--verbose", action="store_true")
    pb.set_defaults(func=cmd_binary)

    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
