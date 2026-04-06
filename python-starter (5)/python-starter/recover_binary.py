#!/usr/bin/env python3
"""
Recover secret via binary search + probe (wraps find_secret.py binary).

Without --oracle, tries in order until one is not rejected:
  1) implicit (return 0/1)
  2) termination (infinite loop vs return)
  3) timing (long vs short finite loops, wall-clock median)

Pass --oracle explicitly to run only that strategy. For timing, use a generous
--timeout (e.g. 90) and maybe --timing-samples 11 on busy Andrew hosts.
"""

from __future__ import annotations

import sys

import find_secret


def main() -> int:
    rest = list(sys.argv[1:])

    if "--oracle" in rest:
        return find_secret.main(["binary", *rest])

    for label, extra in (
        ("implicit", []),
        ("termination", ["--oracle", "termination"]),
        ("timing", ["--oracle", "timing"]),
    ):
        if label != "implicit":
            print(f"recover_binary: trying {label} oracle...", file=sys.stderr)
        code = find_secret.main(["binary", *extra, *rest])
        if code != 4:
            return code
        print(f"recover_binary: {label} oracle was insecure (exit 4).", file=sys.stderr)

    print(
        "recover_binary: all built-in oracles were insecure on this server.",
        file=sys.stderr,
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
