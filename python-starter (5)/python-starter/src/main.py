import os
import socket
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

from parse import file_parse
from infoflow import check_secure

def debug(msg: str) -> None:
    try:
        print(f"[debug] {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


def print_and_exit(msg: str, code: int) -> None:
    try:
        print(msg)
    except BrokenPipeError:
        pass
    raise SystemExit(code)


def main() -> None:
    argv = sys.argv[1:]
    if len(argv) != 1:
        debug(f"host={socket.gethostname()} invalid_args argv={argv}")
        print_and_exit("error", 1)
    filename = argv[0]
    debug(f"host={socket.gethostname()} file={filename} stage=start")
    try:
        with open(filename, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception as e:
        debug(f"host={socket.gethostname()} file={filename} stage=read_failed error={type(e).__name__}: {e}")
        print_and_exit("error", 1)

    debug(f"host={socket.gethostname()} file={filename} stage=parse_start")
    try:
        prog = file_parse(src)
    except Exception as e:
        debug(f"host={socket.gethostname()} file={filename} stage=parse_failed error={type(e).__name__}: {e}")
        print_and_exit("error", 1)

    debug(f"host={socket.gethostname()} file={filename} stage=check_start")
    try:
        secure = check_secure(prog)
    except NotImplementedError:
        debug(f"host={socket.gethostname()} file={filename} stage=check_failed error=NotImplementedError")
        print_and_exit("error", 1)
    except Exception as e:
        debug(f"host={socket.gethostname()} file={filename} stage=check_failed error={type(e).__name__}: {e}")
        print_and_exit("error", 1)

    debug(f"host={socket.gethostname()} file={filename} stage=done result={'secure' if secure else 'insecure'}")
    if secure:
        print_and_exit("secure", 0)
    else:
        print_and_exit("insecure", 2)


if __name__ == "__main__":
    main()
