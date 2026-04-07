from __future__ import annotations

import sys
import find_secret


def main() -> int:
    rest = list(sys.argv[1:])

    # If user explicitly chose oracle, just pass through
    if "--oracle" in rest:
        return find_secret.main(["binary", *rest])

    print(
        "recover_binary: trying lecture-based oracle families:\n"
        "  implicit\n"
        "  termination\n"
        "  timing\n",
        file=sys.stderr,
    )

    attempts = [
        ("implicit", []),
        ("termination", ["--oracle", "termination"]),
        ("timing", ["--oracle", "timing"]),
    ]

    for label, extra in attempts:
        print(f"recover_binary: trying {label} oracle...", file=sys.stderr)
        rc = find_secret.main(["binary", *extra, *rest])

        if rc != 4:
            return rc

        print(f"recover_binary: {label} oracle was insecure (exit 4).", file=sys.stderr)

    print(
        "\nrecover_binary: ALL ORACLES REJECTED\n"
        "Lecture interpretation:\n"
        "  - implicit flow blocked\n"
        "  - termination channel blocked\n"
        "  - timing channel blocked\n\n"
        "=> This server is stronger than built-in attacks OR fully secure.\n"
        "=> You must analyze accepted programs (run check) instead of retrying.\n",
        file=sys.stderr,
    )

    return 4


if __name__ == "__main__":
    raise SystemExit(main())