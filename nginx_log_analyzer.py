import argparse
import gzip
import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

LOG_DIR = Path("/var/log/nginx")

ACCESS_PATTERN = re.compile(
    r'(?P<ip>\S+) - .*? \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>[0-9]{3}) \S+ '
    r'"[^"]*" "(?P<agent>[^"]*)"(?:\s|$)'
)
ERROR_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>\w+)\] \d+#\d+: (?P<message>.*)'
)
STATUS_PATTERN = re.compile(r"[0-9]{3}")
LOG_NAME_PATTERN = re.compile(r"\.(?:log|json|jsonl|ndjson)(?:\.[0-9]+)?(?:\.gz)?$", re.I)
JSON_NAME_PATTERN = re.compile(r"\.(?:json|jsonl|ndjson)(?:\.[0-9]+)?(?:\.gz)?$", re.I)

SUSPICIOUS_PATTERNS = (
    ".env", ".git", "wp-admin", "phpmyadmin", "xmlrpc.php", "/vendor/", "id_rsa", ".sql",
)
BOT_MARKERS = ("bot", "crawler", "spider", "curl", "wget", "python")
UPSTREAM_SEPARATOR = re.compile(r"\s*,\s*|\s+:\s+")
RELATIVE_TIME = re.compile(r"([0-9]+)([smhd])")


@dataclass
class AccessRecord:
    ip: str
    target: str
    status: str
    agent: str
    timestamp: str = ""
    request_time: object = None
    upstream_addr: str = ""
    upstream_response_time: str = ""
    upstream_status: str = ""


class TimeFilter:
    def __init__(self, since):
        self.since = since
        self.older = 0
        self.missing = 0

    def accepts(self, timestamp):
        if self.since is None:
            return True
        try:
            instant = parse_timestamp(timestamp)
        except (ValueError, OverflowError, OSError):
            self.missing += 1
            return False
        if instant < self.since:
            self.older += 1
            return False
        return True


def parse_timestamp(value):
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        if value[:4].isdigit() and "/" in value:
            instant = datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
        else:
            instant = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    return instant.astimezone(timezone.utc)


def parse_since(value):
    try:
        relative = RELATIVE_TIME.fullmatch(value)
        if relative:
            amount, unit = relative.groups()
            seconds = int(amount) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
            return datetime.now(timezone.utc) - timedelta(seconds=seconds)
        return parse_timestamp(value)
    except (ValueError, OverflowError, OSError) as error:
        raise argparse.ArgumentTypeError("use an ISO-8601 time or an interval like 15m, 2h or 7d") from error


def milliseconds(value):
    if type(value) not in (int, float, str):
        return None
    try:
        seconds = float(value)
    except (ValueError, OverflowError):
        return None
    duration = seconds * 1000
    return round(duration) if duration >= 0 and math.isfinite(duration) else None


def latency_row(histogram):
    count = sum(histogram.values())
    median_rank = (count + 1) // 2
    p95_rank = (count * 95 + 99) // 100
    cumulative = 0
    p50 = None
    for duration, frequency in sorted(histogram.items()):
        cumulative += frequency
        if p50 is None and cumulative >= median_rank:
            p50 = duration
        if cumulative >= p95_rank:
            return count, p50, duration


def print_latency(title, groups):
    if not groups:
        return
    rows = [(label, *latency_row(values)) for label, values in groups.items()]
    rows.sort(key=lambda row: (-row[3], -row[1], row[0]))
    print(f"\n--- {title} ---")
    print("TARGET\tSAMPLES\tP50_MS\tP95_MS")
    for label, count, p50, p95 in rows[:10]:
        print(f"{label}\t{count}\t{p50}\t{p95}")


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

    return AccessRecord(
        ip, uri, str(status), agent or "-",
        timestamp=data["time"] if isinstance(data.get("time"), str) else "",
        request_time=data.get("request_time"),
        upstream_addr=data["upstream_addr"] if isinstance(data.get("upstream_addr"), str) else "",
        upstream_response_time=_metric_text(data.get("upstream_response_time")),
        upstream_status=_metric_text(data.get("upstream_status")),
    )


def _metric_text(value):
    return str(value) if type(value) in (int, float, str) else ""


def parse_combined_access(line):
    match = ACCESS_PATTERN.match(line)
    if not match:
        return None
    request = match["request"].split(maxsplit=2)
    target = request[1] if len(request) > 1 else "-"
    return AccessRecord(match["ip"], target, match["status"], match["agent"], match["timestamp"])


class AccessAnalyzer:
    def __init__(self, parse_line, since=None):
        self.parse_line = parse_line
        self.time_filter = TimeFilter(since)
        self.request_latency = Counter()
        self.path_latency = defaultdict(Counter)
        self.upstream_latency = defaultdict(Counter)
        self.upstream_errors = Counter()
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
        if record is None or not self.time_filter.accepts(record.timestamp):
            return

        ip, status, agent = record.ip, record.status, record.agent
        uri = request_path(record.target)
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

        if (duration := milliseconds(record.request_time)) is not None:
            self.request_latency[duration] += 1
            self.path_latency[uri][duration] += 1
        if record.upstream_addr:
            self.record_upstreams(record)

    def record_upstreams(self, record):
        addresses = UPSTREAM_SEPARATOR.split(record.upstream_addr.strip())
        durations = UPSTREAM_SEPARATOR.split(record.upstream_response_time.strip())
        statuses = UPSTREAM_SEPARATOR.split(record.upstream_status.strip())
        for index, address in enumerate(addresses):
            if not address or address == "-":
                continue
            if len(durations) == len(addresses):
                duration = milliseconds(durations[index])
                if duration is not None:
                    self.upstream_latency[address][duration] += 1
            if len(statuses) == len(addresses):
                status = statuses[index]
                if STATUS_PATTERN.fullmatch(status) and status.startswith(("4", "5")):
                    self.upstream_errors[f"{address} HTTP {status}"] += 1

    def progress(self):
        return f"Requests: {self.parsed} | 4xx: {self.errors_4xx} | 5xx: {self.errors_5xx}"

    def report(self):
        print_report_header("ACCESS LOG REPORT", self.parsed, self.total, self.time_filter)
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
        if self.request_latency:
            print_latency("REQUEST LATENCY", {"all": self.request_latency})
        print_latency("REQUEST LATENCY BY PATH", self.path_latency)
        print_latency("UPSTREAM RESPONSE TIME", self.upstream_latency)
        if self.upstream_errors:
            print_top("UPSTREAM ERRORS (PER ATTEMPT)", self.upstream_errors, 10, 60)


class ErrorAnalyzer:
    def __init__(self, since=None):
        self.time_filter = TimeFilter(since)
        self.levels = Counter()
        self.messages = Counter()
        self.total = 0
        self.parsed = 0

    def process_line(self, line):
        self.total += 1
        match = ERROR_PATTERN.match(line)
        if not match or not self.time_filter.accepts(match["timestamp"]):
            return

        self.parsed += 1
        self.levels[match["level"]] += 1
        normalized = re.sub(r'\*\d+', '*ID', match["message"])
        normalized = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', normalized)
        self.messages[normalized] += 1

    def progress(self):
        return f"Errors parsed: {self.parsed}"

    def report(self):
        print_report_header("ERROR LOG REPORT", self.parsed, self.total, self.time_filter)
        print_top("ERROR LEVELS", self.levels, None, 15)
        print_top("TOP ERRORS", self.messages, 15, 130)


def print_report_header(title, parsed, total, time_filter):
    print(f"\n{'=' * 80}\n{title}\n{'=' * 80}")
    print(f"\nParsed: {parsed}/{total}")
    print(f"Skipped: {total - parsed - time_filter.older - time_filter.missing}")
    if time_filter.since is not None:
        print(f"Older than --since: {time_filter.older}")
        print(f"Missing or invalid timestamp: {time_filter.missing}")


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


def analyze(path, log_type, tail=False, since=None):
    print(f"\nSelected: {path}")
    print(f"Log type: {log_type}")
    if log_type == "error":
        analyzer = ErrorAnalyzer(since)
    else:
        parse_line = parse_json_access if log_type == "json" else parse_combined_access
        analyzer = AccessAnalyzer(parse_line, since)

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
    parser.add_argument("--since", type=parse_since, help="include records from this ISO time or interval (e.g. 2h)")
    args = parser.parse_args()

    try:
        path = args.path if args.path is not None else choose_log(args.log_dir)
        if not path.is_file():
            raise ValueError(f"Not a regular log file: {path}")
        if args.tail and is_gzipped(path):
            raise ValueError("--tail requires an uncompressed log file")
        log_type = detect_log_type(path) if args.type == "auto" else args.type
        analyze(path, log_type, tail=args.tail, since=args.since)
    except (OSError, ValueError, EOFError) as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
