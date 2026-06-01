import re
import sys
import json
import time
import argparse
from pathlib import Path
from collections import Counter

LOG_DIR = "/var/log/nginx"

# ==========================================
# ACCESS LOG REGEX
# ==========================================

ACCESS_PATTERN = re.compile(
    r'(?P<ip>\S+) - - '
    r'\[(?P<time>.*?)\] '
    r'"(?P<request>.*?)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<referer>.*?)" '
    r'"(?P<agent>.*?)"'
)

# ==========================================
# ERROR LOG REGEX
# ==========================================

ERROR_PATTERN = re.compile(
    r'(?P<date>\d+/\d+/\d+ \d+:\d+:\d+) '
    r'\[(?P<level>\w+)\] '
    r'(?P<pid>\d+#\d+): '
    r'(?P<message>.*)'
)

# ==========================================
# SUSPICIOUS PATTERNS
# ==========================================

SUSPICIOUS_PATTERNS = [
    ".env",
    ".git",
    "wp-admin",
    "phpmyadmin",
    "xmlrpc.php",
    "/vendor/",
    "id_rsa",
    ".sql",
]

# ==========================================
# HELPERS
# ==========================================

def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024

    return f"{size:.1f} TB"


def list_logs():
    path = Path(LOG_DIR)

    if not path.exists():
        print(f"Directory not found: {LOG_DIR}")
        sys.exit(1)

    logs = sorted(path.glob("*log")) + sorted(path.glob("*.json"))

    if not logs:
        print("No logs found.")
        sys.exit(1)

    print("\nAvailable nginx logs:\n")

    for i, log in enumerate(logs, start=1):
        size = human_size(log.stat().st_size)

        print(f"[{i}] {log.name:35} {size}")

    return logs


def choose_log(logs):
    while True:
        try:
            choice = int(input("\nSelect log number: "))

            if 1 <= choice <= len(logs):
                return logs[choice - 1]

        except ValueError:
            pass

        print("Invalid choice.")


def detect_log_type(path):
    name = path.name.lower()

    if "error" in name:
        return "error"

    if path.suffix == ".json":
        return "json"

    return "access"


def parse_request(request):
    parts = request.split()

    method = parts[0] if len(parts) > 0 else "-"
    uri = parts[1] if len(parts) > 1 else "-"
    protocol = parts[2] if len(parts) > 2 else "-"

    return method, uri, protocol


# ==========================================
# ACCESS ANALYZER
# ==========================================

class AccessAnalyzer:
    def __init__(self):
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

    def process_line(self, line, json_mode=False):
        self.total += 1

        try:
            if json_mode:
                data = json.loads(line)

                ip = data.get("ip", "-")
                uri = data.get("uri", "-")
                status = str(data.get("status", "-"))
                agent = data.get("agent", "-")

            else:
                match = ACCESS_PATTERN.match(line)

                if not match:
                    return

                raw = match.groupdict()

                _, uri, _ = parse_request(raw["request"])

                ip = raw["ip"]
                status = raw["status"]
                agent = raw["agent"]

            self.parsed += 1

            self.ip_counter[ip] += 1
            self.uri_counter[uri] += 1
            self.status_counter[status] += 1

            if status.startswith("4"):
                self.errors_4xx += 1

            if status.startswith("5"):
                self.errors_5xx += 1

            if status == "404":
                self.top_404[uri] += 1

            if any(bot in agent.lower() for bot in [
                "bot",
                "crawler",
                "spider",
                "curl",
                "wget",
                "python",
            ]):
                self.bot_counter[agent] += 1

            lower_uri = uri.lower()

            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in lower_uri:
                    self.suspicious[uri] += 1

        except Exception:
            return

    def report(self):
        print("\n" + "=" * 80)
        print("ACCESS LOG REPORT")
        print("=" * 80)

        print(f"\nParsed: {self.parsed}/{self.total}")

        print("\n--- STATUS CODES ---")
        for status, count in self.status_counter.most_common():
            print(f"{status}: {count}")

        print(f"\n4xx: {self.errors_4xx}")
        print(f"5xx: {self.errors_5xx}")

        print("\n--- TOP IP ---")
        for ip, count in self.ip_counter.most_common(10):
            print(f"{ip:40} {count}")

        print("\n--- TOP URI ---")
        for uri, count in self.uri_counter.most_common(10):
            print(f"{uri[:90]:95} {count}")

        print("\n--- TOP 404 ---")
        for uri, count in self.top_404.most_common(10):
            print(f"{uri[:90]:95} {count}")

        print("\n--- BOTS ---")
        for agent, count in self.bot_counter.most_common(10):
            print(f"{agent[:100]:105} {count}")

        print("\n--- SUSPICIOUS ---")
        for uri, count in self.suspicious.most_common(10):
            print(f"{uri[:90]:95} {count}")


# ==========================================
# ERROR ANALYZER
# ==========================================

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

        data = match.groupdict()

        level = data["level"]
        message = data["message"]

        self.levels[level] += 1

        # normalize dynamic parts
        normalized = re.sub(r'\*\d+', '*ID', message)
        normalized = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', normalized)

        self.messages[normalized] += 1

    def report(self):
        print("\n" + "=" * 80)
        print("ERROR LOG REPORT")
        print("=" * 80)

        print(f"\nParsed: {self.parsed}/{self.total}")

        print("\n--- ERROR LEVELS ---")
        for level, count in self.levels.most_common():
            print(f"{level:15} {count}")

        print("\n--- TOP ERRORS ---")
        for msg, count in self.messages.most_common(15):
            short = msg[:130] + "..." if len(msg) > 130 else msg
            print(f"{short:135} {count}")


# ==========================================
# TAIL MODE
# ==========================================

def follow(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.1)
                continue

            yield line


# ==========================================
# MAIN ANALYSIS
# ==========================================

def analyze(path, tail=False):
    log_type = detect_log_type(path)

    print(f"\nSelected: {path.name}")
    print(f"Detected type: {log_type}")

    if log_type in ["access", "json"]:
        analyzer = AccessAnalyzer()

        if tail:
            print("\nRealtime mode. CTRL+C to stop.\n")

            try:
                for line in follow(path):
                    analyzer.process_line(
                        line,
                        json_mode=(log_type == "json")
                    )

                    sys.stdout.write(
                        f"\rRequests: {analyzer.parsed} | "
                        f"4xx: {analyzer.errors_4xx} | "
                        f"5xx: {analyzer.errors_5xx}"
                    )

                    sys.stdout.flush()

            except KeyboardInterrupt:
                print("\n")

        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    analyzer.process_line(
                        line,
                        json_mode=(log_type == "json")
                    )

        analyzer.report()

    else:
        analyzer = ErrorAnalyzer()

        if tail:
            print("\nRealtime mode. CTRL+C to stop.\n")

            try:
                for line in follow(path):
                    analyzer.process_line(line)

                    sys.stdout.write(
                        f"\rErrors parsed: {analyzer.parsed}"
                    )

                    sys.stdout.flush()

            except KeyboardInterrupt:
                print("\n")

        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    analyzer.process_line(line)

        analyzer.report()


# ==========================================
# ENTRYPOINT
# ==========================================

def main():
    parser = argparse.ArgumentParser(
        description="Universal nginx log analyzer"
    )

    parser.add_argument(
        "--tail",
        action="store_true",
        help="Realtime mode"
    )

    args = parser.parse_args()

    logs = list_logs()

    selected = choose_log(logs)

    analyze(selected, tail=args.tail)


if __name__ == "__main__":
    main()
