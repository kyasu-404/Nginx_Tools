"""Summarize HTTP virtual hosts and upstreams from an nginx configuration dump."""

import argparse
import json
import posixpath
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase

from _nginx_config import CONFIG_ERRORS, add_nginx_options, read_dump, split_dump

TOKEN = re.compile(
    r"(?P<space>\s+)|(?P<comment>#[^\n]*)|(?P<punct>[{};])|"
    r"""(?P<word>(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"|"""
    r"""\$\{[^{}\s]+\}|\\.|[^\s{};'\"\\])+)|(?P<invalid>.)""",
    re.DOTALL,
)
PASS = {"proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"}


@dataclass
class Directive:
    name: str
    args: list
    source: str
    line: int
    children: list | None


def tokens(text, source):
    line = 1
    for match in TOKEN.finditer(text):
        value = match.group()
        kind = match.lastgroup
        if kind == "invalid":
            raise ValueError(f"{source}:{line}: unexpected character {value!r}")
        if kind in ("word", "punct"):
            if kind == "word" and len(value) > 1 and value[0] in "'\"" and value[-1] == value[0]:
                value = value[1:-1]
            if kind == "word":
                value = re.sub(r"""\\([ "'\\])""", r"\1", value)
            yield kind, value, line
        line += match.group().count("\n")


def parse_config(text, source):
    root = []
    blocks = [root]
    words = []
    start_line = 1
    for kind, value, line in tokens(text, source):
        if kind == "word":
            if not words:
                start_line = line
            words.append(value)
        elif value == "}" and not words and len(blocks) > 1:
            blocks.pop()
        elif value in ("{", ";") and words:
            children = [] if value == "{" else None
            blocks[-1].append(Directive(words[0], words[1:], source, start_line, children))
            if children is not None:
                blocks.append(children)
            words = []
        else:
            raise ValueError(f"{source}:{line}: unexpected {value!r}")
    if words or len(blocks) != 1:
        raise ValueError(f"{source}:{start_line}: incomplete directive or block")
    return root


def matches_glob(path, pattern):
    parts, patterns = path.split("/"), pattern.split("/")
    return len(parts) == len(patterns) and all(
        (not part.startswith(".") or mask.startswith(".")) and fnmatchcase(part, mask)
        for part, mask in zip(parts, patterns)
    )


class Config:
    def __init__(self, files):
        self.files = {posixpath.normpath(path): (path, text) for path, text in files.items()}
        self.main = next(iter(self.files))
        self.base = posixpath.dirname(self.main)
        self.parsed = {}

    def expand_file(self, path, stack):
        if path in stack:
            raise ValueError(f"Recursive include: {' -> '.join((*stack, path))}")
        if path not in self.parsed:
            source, text = self.files[path]
            self.parsed[path] = parse_config(text, source)
        yield from self.expand(self.parsed[path], (*stack, path))

    def expand(self, directives, stack):
        for directive in directives:
            if directive.name != "include" or directive.children is not None:
                yield directive, stack
                continue
            if len(directive.args) != 1:
                raise ValueError(f"{directive.source}:{directive.line}: invalid include")
            pattern = posixpath.normpath(posixpath.join(self.base, directive.args[0]))
            if pattern in self.files:
                paths = [pattern]
            elif any(char in pattern for char in "*?["):
                paths = sorted(path for path in self.files if matches_glob(path, pattern))
            else:
                raise ValueError(f"{directive.source}:{directive.line}: missing dump section {pattern}")
            for path in paths:
                yield from self.expand_file(path, stack)

    def backend_targets(self, directives):
        for directive, stack in directives:
            if directive.name in PASS and directive.args:
                yield f"{directive.name} {directive.args[0]}"
            if directive.children is not None:
                yield from self.backend_targets(self.expand(directive.children, stack))


def socket_label(value):
    if value.isdecimal():
        return f"*:{value}"
    if value.startswith("0.0.0.0:"):
        return "*:" + value.split(":", 1)[1]
    if value.startswith("unix:") or (":" in value and not value.endswith("]")):
        return value
    return f"{'*' if value == '0.0.0.0' else value}:80"


def inventory(files):
    config = Config(files)
    vhosts = []
    upstreams = []
    defaults = {}
    for http, http_stack in config.expand_file(config.main, ()):
        if http.name != "http" or http.children is None:
            continue
        for directive, stack in config.expand(http.children, http_stack):
            if directive.children is None:
                continue
            if directive.name == "upstream" and directive.args:
                members = config.expand(directive.children, stack)
                upstreams.append({
                    "name": directive.args[0],
                    "servers": [" ".join(member.args) for member, _ in members if member.name == "server"],
                    "file": directive.source, "line": directive.line,
                })
            elif directive.name == "server":
                children = list(config.expand(directive.children, stack))
                names = [name for item, _ in children if item.name == "server_name" for name in item.args]
                listeners = [item.args for item, _ in children if item.name == "listen" and item.args]
                vhost = {
                    "names": names, "listen": [" ".join(listener) for listener in listeners],
                    "file": directive.source, "line": directive.line,
                    "targets": list(dict.fromkeys(config.backend_targets(children))),
                }
                vhosts.append(vhost)
                for listener in listeners:
                    address = socket_label(listener[0])
                    transport = "udp" if "quic" in listener[1:] else "tcp"
                    socket_key = (address, transport)
                    explicit = "default_server" in listener[1:] or "default" in listener[1:]
                    if explicit or socket_key not in defaults:
                        defaults[socket_key] = {
                            "listen": address, "transport": transport, "explicit": explicit, "names": names,
                            "file": directive.source, "line": directive.line,
                        }

    return {"vhosts": vhosts, "default_servers": list(defaults.values()), "upstreams": upstreams}


def print_inventory(result):
    print("SERVER NAME\tLISTEN\tCONFIG\tBACKEND")
    for row in result["vhosts"]:
        print(f"{' '.join(row['names']) or '(no name)'}\t{', '.join(row['listen']) or '(implicit)'}"
              f"\t{row['file']}:{row['line']}\t{', '.join(row['targets']) or '-'}")

    if result["default_servers"]:
        print("\nLISTEN\tTRANSPORT\tDEFAULT SERVER\tSELECTION\tCONFIG")
        for row in result["default_servers"]:
            mode = "explicit" if row["explicit"] else "first"
            print(f"{row['listen']}\t{row['transport']}\t{' '.join(row['names']) or '(no name)'}"
                  f"\t{mode}\t{row['file']}:{row['line']}")

    if result["upstreams"]:
        print("\nUPSTREAM\tSERVERS\tCONFIG")
        for row in result["upstreams"]:
            print(f"{row['name']}\t{', '.join(row['servers']) or '-'}\t{row['file']}:{row['line']}")


def main():
    parser = argparse.ArgumentParser(description="List HTTP virtual hosts from nginx -T")
    add_nginx_options(parser)
    parser.add_argument("--dump", help="read a saved nginx -T dump (or - for stdin)")
    parser.add_argument("--json", action="store_true", help="output results as JSON")
    args = parser.parse_args()
    try:
        result = inventory(split_dump(read_dump(args.dump, args)))
    except CONFIG_ERRORS as error:
        parser.error(str(error))

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_inventory(result)


if __name__ == "__main__":
    main()
