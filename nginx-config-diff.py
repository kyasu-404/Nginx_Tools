"""Save nginx -T snapshots and compare their configuration files."""

import argparse
import difflib
import os
import tempfile
from pathlib import Path

from _nginx_config import CONFIG_ERRORS, add_nginx_options, read_dump, split_dump


def save_snapshot(destination, dump):
    split_dump(dump)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=destination.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(dump)
        os.link(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink()


def show_diff(before, after):
    changed = False
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        changed = True
        if not old and not new:
            action = "Added" if old is None else "Removed"
            print(f"{action} empty file: {path}")
            continue

        for line in difflib.unified_diff(
            (old or "").splitlines(keepends=True), (new or "").splitlines(keepends=True),
            fromfile=f"before:{path}" if old is not None else "/dev/null",
            tofile=f"after:{path}" if new is not None else "/dev/null",
        ):
            if line.endswith("\n"):
                print(line, end="")
            else:
                print(line)
                print(r"\ No newline at end of file")

    if not changed:
        print("No configuration changes.")
    return int(changed)


def main():
    parser = argparse.ArgumentParser(description="Save or compare nginx configuration snapshots")
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot", help="save a new nginx -T snapshot")
    add_nginx_options(snapshot)
    snapshot.add_argument("output", type=Path)
    snapshot.add_argument("--dump", help="save from an existing nginx -T dump (or - for stdin)")
    diff = commands.add_parser("diff", help="compare a saved snapshot with another dump or with disk")
    add_nginx_options(diff)
    diff.add_argument("before", help="saved nginx -T dump")
    diff.add_argument("after", nargs="?", help="second dump (defaults to a live nginx -T read)")
    args = parser.parse_args()

    try:
        if args.command == "snapshot":
            save_snapshot(args.output, read_dump(args.dump, args))
            print(f"Saved {args.output}")
            return 0
        if args.before == args.after == "-":
            parser.error("Only one side of a diff can read stdin.")
        before = split_dump(read_dump(args.before, args))
        after = split_dump(read_dump(args.after, args))
        return show_diff(before, after)
    except CONFIG_ERRORS as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
