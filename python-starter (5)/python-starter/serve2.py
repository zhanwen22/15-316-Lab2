#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXAMPLES = ROOT / "examples"

SERVE = "~mfredrik/bin/c0_serve2"
DEFAULT_USERID = "wennaz"

C0_FILES = {
    "probe": str(EXAMPLES / "probe.c0"),
    "implicit_safe": str(EXAMPLES / "compare_secret_to_input.c0"),
    "term_safe": str(EXAMPLES / "compare_via_termination.c0"),
    "timing_safe": str(EXAMPLES / "compare_timing_branches.c0"),
    "implicit_attack": str(EXAMPLES / "compare_secret_to_input_attack.c0"),
    "term_attack": str(EXAMPLES / "compare_via_termination_attack.c0"),
    "timing_attack": str(EXAMPLES / "compare_timing_branches_attack.c0"),
}

_SUCCESS = re.compile(r"^success\s+(-?\d+)\s*$", re.MULTILINE)
_FAILURE = re.compile(r"^failure\s+(-?\d+)\s*$", re.MULTILINE)
_INSECURE = re.compile(r"^insecure\s*$", re.MULTILINE)
_ABORT = re.compile(r"^abort\s*$", re.MULTILINE)
_ERROR = re.compile(r"^error\s*$", re.MULTILINE)


def run2(userid: str, c0_path: str, inp: int, timeout: float) -> tuple[str, str, int | None]:
    cmd = f"{SERVE} {shlex.quote(userid)} {shlex.quote(c0_path)} {inp}"
    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    return out, err, proc.returncode


def classify(stdout: str) -> str:
    s = stdout.strip()
    if _INSECURE.search(s):
        return "insecure"
    if _ABORT.search(s):
        return "abort"
    if _ERROR.search(s):
        return "error"
    if _SUCCESS.search(s):
        return "success"
    if _FAILURE.search(s):
        return "failure"
    if not s:
        return "(empty)"
    return "other"


def extract_value(stdout: str) -> int | None:
    m = _SUCCESS.search(stdout)
    if m:
        return int(m.group(1))
    m = _FAILURE.search(stdout)
    if m:
        return int(m.group(1))
    return None


def cmd_check(args: argparse.Namespace) -> int:
    userid = args.userid
    timeout = args.timeout
    test_input = args.test_input

    print(f"server2 check: userid={userid} input={test_input}", file=sys.stderr)
    print(f"cwd={Path.cwd()}", file=sys.stderr)
    print("", file=sys.stderr)

    accepted = []
    rejected = []

    for label, path in C0_FILES.items():
        p = Path(path)
        if not p.is_file():
            print(f"{label:16} MISSING {path}", file=sys.stderr)
            continue

        try:
            out, err, rc = run2(userid, str(p), test_input, timeout)
        except subprocess.TimeoutExpired:
            print(f"{label:16} TIMEOUT (> {timeout}s)", file=sys.stderr)
            continue

        cat = classify(out)
        val = extract_value(out)
        line = f"{label:16} {cat:10} rc={rc}"
        if val is not None:
            line += f" value={val}"
        if out:
            line += f" stdout={out!r}"
        if err:
            line += f" stderr={err!r}"
        print(line, file=sys.stderr)

        if cat == "insecure":
            rejected.append(label)
        else:
            accepted.append((label, cat))

    print("", file=sys.stderr)
    print(f"accepted/non-insecure: {accepted}", file=sys.stderr)
    print(f"rejected as insecure: {rejected}", file=sys.stderr)

    if not accepted:
        print(
            "\nNo built-in example was accepted on server 2.\n"
            "That usually means either server 2 is the strongest one,\n"
            "or it requires a custom oracle not present in examples/.",
            file=sys.stderr,
        )
        return 2

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    userid = args.userid
    c0_path = args.file
    inp = args.input
    timeout = args.timeout

    if not Path(c0_path).is_file():
        print(f"missing file: {c0_path}", file=sys.stderr)
        return 1

    try:
        out, err, rc = run2(userid, c0_path, inp, timeout)
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT (> {timeout}s)", file=sys.stderr)
        return 124

    cat = classify(out)
    val = extract_value(out)

    print(f"classification: {cat}")
    print(f"returncode: {rc}")
    if val is not None:
        print(f"value: {val}")
    if out:
        print(f"stdout: {out}")
    if err:
        print(f"stderr: {err}", file=sys.stderr)

    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    userid = args.userid
    c0_path = args.file
    timeout = args.timeout
    start = args.start
    stop = args.stop
    step = args.step

    if step == 0:
        print("step must not be 0", file=sys.stderr)
        return 1
    if not Path(c0_path).is_file():
        print(f"missing file: {c0_path}", file=sys.stderr)
        return 1

    print("input\tclassification\trc\tvalue\tstdout", flush=True)
    for inp in range(start, stop, step):
        try:
            out, err, rc = run2(userid, c0_path, inp, timeout)
            cat = classify(out)
            val = extract_value(out)
            val_s = "" if val is None else str(val)
            print(f"{inp}\t{cat}\t{rc}\t{val_s}\t{out}")
            if err:
                print(f"# stderr for input={inp}: {err}", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print(f"{inp}\ttimeout\t\t\t")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Server 2 diagnostics: check built-in examples, run one file, or sweep inputs."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="See how server 2 classifies each built-in example .c0")
    pc.add_argument("--userid", default=DEFAULT_USERID)
    pc.add_argument("--timeout", type=float, default=15.0)
    pc.add_argument("--test-input", type=int, default=42, dest="test_input")
    pc.set_defaults(func=cmd_check)

    pr = sub.add_parser("run", help="Run one .c0 file on one input")
    pr.add_argument("file", help="Path to .c0 file")
    pr.add_argument("input", type=int, help="Low input value")
    pr.add_argument("--userid", default=DEFAULT_USERID)
    pr.add_argument("--timeout", type=float, default=30.0)
    pr.set_defaults(func=cmd_run)

    ps = sub.add_parser("sweep", help="Run one .c0 file across a range of inputs")
    ps.add_argument("file", help="Path to .c0 file")
    ps.add_argument("--start", type=int, default=0)
    ps.add_argument("--stop", type=int, default=16)
    ps.add_argument("--step", type=int, default=1)
    ps.add_argument("--userid", default=DEFAULT_USERID)
    ps.add_argument("--timeout", type=float, default=30.0)
    ps.set_defaults(func=cmd_sweep)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())