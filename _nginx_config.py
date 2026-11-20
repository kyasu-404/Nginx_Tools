"""Read the file sections emitted by nginx -T."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

FILE_HEADER = re.compile(r"^# configuration file (.+):\r?$", re.MULTILINE)


def add_nginx_options(parser):
    parser.add_argument("--nginx", default="nginx", help="nginx executable for live reads")
    parser.add_argument("--config", type=Path, help="alternate nginx.conf for live reads")
    parser.add_argument("--prefix", type=Path, help="nginx prefix directory for live reads")


def read_dump(source, args):
    if source == "-":
        return sys.stdin.read()
    if source is not None:
        with Path(source).open(encoding="utf-8", newline="") as file:
            return file.read()

    command = [args.nginx, "-T"]
    if args.config is not None:
        command.extend(("-c", str(args.config)))
    if args.prefix is not None:
        command.extend(("-p", str(args.prefix)))
    result = subprocess.run(command, capture_output=True, timeout=30)
    if result.stderr:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
    if result.returncode:
        raise ValueError(f"nginx -T exited with status {result.returncode}")
    return result.stdout.decode("utf-8")


def split_dump(dump):
    # The first section is the main configuration. Nginx appends a newline
    # to every section past the bytes of the original config file.
    headers = list(FILE_HEADER.finditer(dump))
    if not headers:
        raise ValueError("No file sections found in nginx -T output.")

    files = {}
    for index, header in enumerate(headers):
        name = header.group(1)
        if name in files:
            raise ValueError(f"Duplicate configuration section: {name}")
        end = headers[index + 1].start() if index + 1 < len(headers) else len(dump)
        content = dump[header.end() + 1:end]
        files[name] = content[:-1] if content.endswith("\n") else content
    return files


CONFIG_ERRORS = (OSError, ValueError, subprocess.TimeoutExpired)
