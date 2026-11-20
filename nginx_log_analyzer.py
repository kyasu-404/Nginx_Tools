import argparse
import gzip
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

LOG_DIR = Path("/var/log/nginx")

ACCESS_PATTERN = re.compile(
    r'(?P<ip>\S+) - .*? \[[^\]]+\] '
    r'"(?P<request>[^"]*)" (?P<status>[0-9]{3}) \S+ '
    r'"[^"]*" "(?P<agent>[^"]*)"(?:\s|$)'
)
ERROR_PATTERN = re.compile(
    r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} '
    r'\[(?P<level>\w+)\] \d+#\d+: (?P<message>.*)'
)
STATUS_PATTERN = re.compile(r"[0-9]{3}")
LOG_NAME_PATTERN = re.compile(r"\.(?:log|json|jsonl|ndjson)(?:\.[0-9]+)?(?:\.gz)?$", re.I)
JSON_NAME_PATTERN = re.compile(r"\.(?:json|jsonl|ndjson)(?:\.[0-9]+)?(?:\.gz)?$", re.I)

SUSPICIOUS_PATTERNS = (
    ".env", ".git", "wp-admin", "phpmyadmin", "xmlrpc.php", "/vendor/", "id_rsa", ".sql",
)
BOT_MARKERS = ("bot", "crawler", "spider", "curl", "wget", "python")


def human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024

    return f"{size:.1f} TB"


def choose_log(directory):
    logs = sorted(
        path for path in directory.iterdir()
        if LOG_NAME_PATTERN.search(path.name) and path.is_file()
    )
    if not logs:
        raise ValueError(f"No logs found in {directory}")

    print("\nAvailable nginx logs:\n")
    for index, log in enumerate(logs, start=1):
        print(f"[{index}] {log.name:35} {human_size(log.stat().st_size)}")

    while True:
        try:
            choice = int(input("\nSelect log number: "))
        except ValueError:
            choice = 0
        except EOFError:
            raise ValueError("No log selected. Pass a log path on the command line.") from None

        if 1 <= choice <= len(logs):
            return logs[choice - 1]

        print("Invalid choice.")


def is_gzipped(path):
    return path.suffix.lower() == ".gz"


def open_log(path):
    opener = gzip.open if is_gzipped(path) else open
    return opener(path, "rt", encoding="utf-8", errors="replace")


def detect_log_type(path):
    with open_log(path) as log:
        for _ in range(32):
            line = log.readline()
            if not line:
                break
            if ACCESS_PATTERN.match(line):
                return "access"
            if ERROR_PATTERN.match(line):
                return "error"
            if line.lstrip().startswith("{"):
                return "json"

    if JSON_NAME_PATTERN.search(path.name):
        return "json"
    return "error" if "error" in path.name.lower() else "access"


def request_path(target):
    if target.lower().startswith(("http://", "https://")):
        try:
            return urlsplit(target).path or "/"
        except ValueError:
            pass
    return target.partition("?")[0] or "-"


def parse_json_access(line):
    try:
        data = json.loads(line)
    except (ValueError, RecursionError):
        return None

    if not isinstance(data, dict):
        return None

    ip = data.get("ip")
    uri = data.get("uri")
    status = data.get("status")
    agent = data.get("agent")
    if not (isinstance(ip, str) and ip and isinstance(uri, str) and uri):
        return None
    if type(status) not in (int, str) or not STATUS_PATTERN.fullmatch(str(status)):
        return None
    if agent is not None and not isinstance(agent, str):
        return None

    return ip, uri, str(status), agent or "-"


def parse_combined_access(line):
    match = ACCESS_PATTERN.match(line)
    if not match:
        return None
    request = match["request"].split(maxsplit=2)
    target = request[1] if len(request) > 1 else "-"
    return match["ip"], target, match["status"], match["agent"]


class AccessAnalyzer:
    def __init__(self, parse_line):
        self.parse_line = parse_line
        self.ip_counter = Counter()
        self.uri_counter = Counter()
        self.status_counter = Counter()
        self.bot_counter = Counter()
        self.top_404 = Counter()
        self.suspicious = Counter()
        self.total = 0
        self.parsed = 0
        self.errors_4xx = 0
        self.errors_5xx = 0

    def process_line(self, line):
        self.total += 1
        record = self.parse_line(line)
        if record is None:
            return

        ip, target, status, agent = record
        uri = request_path(target)
        self.parsed += 1
        self.ip_counter[ip] += 1
        self.uri_counter[uri] += 1
        self.status_counter[status] += 1

        if status.startswith("4"):
            self.errors_4xx += 1
        elif status.startswith("5"):
            self.errors_5xx += 1
        if status == "404":
            self.top_404[uri] += 1

        lower_agent = agent.lower()
        if any(marker in lower_agent for marker in BOT_MARKERS):
            self.bot_counter[agent] += 1

        lower_uri = uri.lower()
        if any(pattern in lower_uri for pattern in SUSPICIOUS_PATTERNS):
            self.suspicious[uri] += 1

    def progress(self):
        return f"Requests: {self.parsed} | 4xx: {self.errors_4xx} | 5xx: {self.errors_5xx}"

    def report(self):
        print_report_header("ACCESS LOG REPORT", self.parsed, self.total)
        print("\n--- STATUS CODES ---")
        for status, count in self.status_counter.most_common():
            print(f"{status}: {count}")
        print(f"\n4xx: {self.errors_4xx}")
        print(f"5xx: {self.errors_5xx}")

        print_top("TOP IP", self.ip_counter, 10, 40)
        print_top("TOP URI", self.uri_counter, 10, 90)
        print_top("TOP 404", self.top_404, 10, 90)
        print_top("BOTS", self.bot_counter, 10, 100)
        print_top("SUSPICIOUS", self.suspicious, 10, 90)


class ErrorAnalyzer:
    def __init__(self):
        self.levels = Counter()
        self.messages = Counter()
        self.total = 0
        self.parsed = 0

    def process_line(self, line):
        self.total += 1
        match = ERROR_PATTERN.match(line)
        if not match:
            return

        self.parsed += 1
        self.levels[match["level"]] += 1
        normalized = re.sub(r'\*\d+', '*ID', match["message"])
        normalized = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', normalized)
        self.messages[normalized] += 1

    def progress(self):
        return f"Errors parsed: {self.parsed}"

    def report(self):
        print_report_header("ERROR LOG REPORT", self.parsed, self.total)
        print_top("ERROR LEVELS", self.levels, None, 15)
        print_top("TOP ERRORS", self.messages, 15, 130)


def print_report_header(title, parsed, total):
    print(f"\n{'=' * 80}\n{title}\n{'=' * 80}")
    print(f"\nParsed: {parsed}/{total}")
    print(f"Skipped: {total - parsed}")


def print_top(title, counter, limit, width):
    print(f"\n--- {title} ---")
    for value, count in counter.most_common(limit):
        value = value if len(value) <= width else value[:width - 3] + "..."
        print(f"{value:{width}}  {count}")


def follow(path):
    checkpoint_size = 256
    log = path.open("rb", buffering=0)
    try:
        offset = log.seek(0, os.SEEK_END)
        log.seek(max(0, offset - checkpoint_size))
        checkpoint = log.read(offset - log.tell())
        fragment = bytearray()
        skip_initial_suffix = bool(checkpoint and not checkpoint.endswith(b"\n"))

        while True:
            chunk = log.read(65536)
            if chunk:
                checkpoint = (checkpoint + chunk[-checkpoint_size:])[-checkpoint_size:]
                lines = chunk.split(b"\n")
                fragment.extend(lines[0])
                if len(lines) > 1:
                    if not skip_initial_suffix:
                        yield fragment.decode("utf-8", errors="replace")
                    skip_initial_suffix = False
                    for line in lines[1:-1]:
                        yield line.decode("utf-8", errors="replace")
                    fragment = bytearray(lines[-1])
                continue

            time.sleep(0.1)
            try:
                current = path.stat()
            except FileNotFoundError:
                current = None

            opened = os.fstat(log.fileno())
            if current is not None and not os.path.samestat(opened, current):
                # Drain writes that reached the old file during the last poll.
                if opened.st_size > log.tell():
                    continue
                try:
                    replacement = path.open("rb", buffering=0)
                except FileNotFoundError:
                    continue
                log.close()
                log = replacement
            else:
                # Check the previous bytes as well as the size: a truncated file
                # can grow back past the old offset before the next poll.
                offset = log.tell()
                log.seek(offset - len(checkpoint))
                if log.read(len(checkpoint)) == checkpoint:
                    continue
                log.seek(0)

            checkpoint = b""
            fragment.clear()
            skip_initial_suffix = False
    finally:
        log.close()


def analyze(path, log_type, tail=False):
    print(f"\nSelected: {path}")
    print(f"Log type: {log_type}")
    if log_type == "error":
        analyzer = ErrorAnalyzer()
    else:
        parse_line = parse_json_access if log_type == "json" else parse_combined_access
        analyzer = AccessAnalyzer(parse_line)

    if tail:
        print("\nRealtime mode. Ctrl+C to stop.\n", flush=True)
        try:
            for line in follow(path):
                analyzer.process_line(line)
                print("\r" + analyzer.progress(), end="", flush=True)
        except KeyboardInterrupt:
            print()
    else:
        with open_log(path) as log:
            for line in log:
                analyzer.process_line(line)

    analyzer.report()


def main():
    parser = argparse.ArgumentParser(description="Analyze nginx access and error logs")
    parser.add_argument("path", nargs="?", type=Path, help="log file to analyze")
    parser.add_argument("--log-dir", type=Path, default=LOG_DIR, help="directory for the interactive menu")
    parser.add_argument("--type", choices=("auto", "access", "error", "json"), default="auto", help="input log format")
    parser.add_argument("--tail", action="store_true", help="follow new records in a plain log file")
    args = parser.parse_args()

    try:
        path = args.path if args.path is not None else choose_log(args.log_dir)
        if not path.is_file():
            raise ValueError(f"Not a regular log file: {path}")
        if args.tail and is_gzipped(path):
            raise ValueError("--tail requires an uncompressed log file")
        log_type = detect_log_type(path) if args.type == "auto" else args.type
        analyze(path, log_type, tail=args.tail)
    except (OSError, ValueError, EOFError) as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
