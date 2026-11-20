"""Check configured HTTP endpoints through curl."""

import argparse
import ipaddress
import json
import math
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit


@dataclass
class Check:
    name: str
    url: str
    statuses: tuple
    location: str | None
    resolve: str | None
    ca_file: Path | None
    timeout: float
    method: str


def read_checks(path):
    with path.open("rb") as file:
        config = tomllib.load(file)

    entries = config.get("check")
    if set(config) != {"check"} or not isinstance(entries, list) or not entries:
        raise ValueError("Use one or more [[check]] tables.")
    for number, entry in enumerate(entries, 1):
        try:
            yield make_check(entry, path.parent)
        except (ValueError, TypeError, UnicodeError) as error:
            raise ValueError(f"Check {number}: {error}") from error


def make_check(entry, directory):
    allowed = {"name", "url", "status", "location", "connect_ip", "ca_file", "timeout", "method"}
    if not isinstance(entry, dict) or entry.keys() - allowed:
        raise ValueError("Expected a check table with supported keys.")
    url = entry.get("url")
    if not isinstance(url, str) or any(character.isspace() or ord(character) < 32 for character in url):
        raise ValueError("url must be an HTTP(S) URL without whitespace.")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None:
        raise ValueError("url must be an HTTP(S) URL without credentials.")
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    if port == 0:
        raise ValueError("URL port must be between 1 and 65535.")

    statuses = entry.get("status", 200)
    if not isinstance(statuses, list):
        statuses = [statuses]
    if not statuses or any(type(status) is not int or not 100 <= status <= 599 for status in statuses):
        raise ValueError("status must be an HTTP status or a nonempty list of statuses.")

    name = entry.get("name", url)
    location = entry.get("location")
    ca_file = entry.get("ca_file")
    for key, value in (("name", name), ("location", location), ("ca_file", ca_file)):
        if key in entry and (not isinstance(value, str) or not value):
            raise ValueError(f"{key} must be a nonempty string.")

    timeout = entry.get("timeout", 10)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds.")
    method = entry.get("method", "GET")
    if method not in ("GET", "HEAD"):
        raise ValueError("method must be GET or HEAD.")

    resolve = None
    if "connect_ip" in entry:
        if not isinstance(entry["connect_ip"], str):
            raise ValueError("connect_ip must be an IPv4 or IPv6 address.")
        address = ipaddress.ip_address(entry["connect_ip"])
        hostname = parts.hostname.encode("idna").decode("ascii")
        if ":" in hostname:
            raise ValueError("Use a DNS name in the URL when setting connect_ip.")
        destination = f"[{address}]" if address.version == 6 else str(address)
        resolve = f"{hostname}:{port}:{destination}"

    return Check(name, url, tuple(statuses), location, resolve,
                 directory / ca_file if ca_file else None, timeout, method)


def curl_timings(data):
    dns = data.get("time_namelookup", 0)
    connect = data.get("time_connect", 0)
    tls = data.get("time_appconnect", 0)
    first_byte = data.get("time_starttransfer", 0)
    return {
        "dns_ms": round(dns * 1000, 2) if dns or connect else None,
        "tcp_ms": round(max(0, connect - dns) * 1000, 2) if connect else None,
        "tls_ms": round(max(0, tls - connect) * 1000, 2) if tls else None,
        "ttfb_ms": round(first_byte * 1000, 2) if first_byte else None,
    }


def run_check(check):
    command = [
        "curl", "--disable", "--silent", "--show-error", "--globoff", "--noproxy", "*",
        "--proto", "=http,https", "--max-time", str(check.timeout),
        "--output", os.devnull, "--write-out", "%{json}",
    ]
    if check.method == "HEAD":
        command.append("--head")
    if check.resolve:
        command.extend(("--resolve", check.resolve))
    if check.ca_file:
        command.extend(("--cacert", str(check.ca_file)))
    command.extend(("--url", check.url))

    try:
        process = subprocess.run(
            command, capture_output=True, text=True, errors="replace", timeout=check.timeout + 2,
        )
    except subprocess.TimeoutExpired:
        return {"name": check.name, "url": check.url, "ok": False, "errors": ["Request timed out."]}

    errors = []
    try:
        data = json.loads(process.stdout)
    except ValueError:
        data = {}
    if process.returncode:
        errors.append(process.stderr.strip() or f"curl exited with status {process.returncode}.")

    status = data.get("http_code")
    location = data.get("redirect_url") or None
    if not process.returncode:
        if status not in check.statuses:
            expected = ", ".join(map(str, check.statuses))
            errors.append(f"Expected HTTP {expected}, got {status or 'no HTTP response'}.")
        if check.location and location != urljoin(check.url, check.location):
            errors.append(f"Expected redirect to {check.location}, got {location or 'no redirect'}.")

    return {
        "name": check.name, "url": check.url, "ok": not errors, "status": status or None,
        "location": location, "remote_ip": data.get("remote_ip") or None,
        **curl_timings(data), "errors": errors,
    }


def print_results(results):
    for result in results:
        outcome = "OK" if result["ok"] else "FAIL"
        print(f"{outcome} {result['name']} [{result.get('status') or '-'}]")
        for error in result["errors"]:
            print(f"  {error}")
        details = [
            f"{label} {result[key]:.2f} ms"
            for key, label in (("dns_ms", "DNS"), ("tcp_ms", "TCP"), ("tls_ms", "TLS"), ("ttfb_ms", "TTFB"))
            if result.get(key) is not None
        ]
        if details:
            print("  " + ", ".join(details))
        if result.get("location"):
            print(f"  Redirect to {result['location']}")


def main():
    parser = argparse.ArgumentParser(description="Check HTTP endpoints and measure request timings")
    parser.add_argument("config", type=Path, help="TOML file with [[check]] tables")
    parser.add_argument("--json", action="store_true", help="output results as JSON")
    args = parser.parse_args()
    try:
        checks = list(read_checks(args.config))
        results = [run_check(check) for check in checks]
    except (OSError, ValueError, OverflowError) as error:
        parser.error(str(error))

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_results(results)
    return int(any(not result["ok"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
