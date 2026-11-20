"""Check the certificate served by each HTTPS virtual host."""

import argparse
import hashlib
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

PEM_CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+.+?-----END CERTIFICATE-----", re.DOTALL
)


def file_fingerprint(path):
    match = PEM_CERTIFICATE.search(path.read_text(encoding="ascii"))
    if not match:
        raise ValueError(f"No PEM certificate in {path}")
    der = ssl.PEM_cert_to_DER_cert(match.group())
    return hashlib.sha256(der).hexdigest()


def check_certificate(hostname, args, context, expected_fingerprint):
    destination = args.connect if args.connect is not None else hostname
    result = {"host": hostname, "port": args.port, "destination": destination, "ok": False}
    try:
        with socket.create_connection((destination, args.port), timeout=args.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                certificate = connection.getpeercert()
                der = connection.getpeercert(binary_form=True)
                result["remote_ip"] = connection.getpeername()[0]
    except (OSError, ValueError) as error:
        return {**result, "errors": [str(error)]}

    expires = ssl.cert_time_to_seconds(certificate["notAfter"])
    days_left = (expires - time.time()) / 86400
    fingerprint = hashlib.sha256(der).hexdigest()
    errors = []
    if days_left < args.days:
        errors.append(f"Certificate expires within {args.days} days.")
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        errors.append("The served leaf certificate differs from the PEM file.")

    return {
        **result, "ok": not errors, "errors": errors,
        "expires_utc": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
        "days_left": round(days_left, 2), "sha256": fingerprint,
        "dns_names": [name for kind, name in certificate.get("subjectAltName", ()) if kind == "DNS"],
    }


def main():
    parser = argparse.ArgumentParser(description="Verify HTTPS certificates and check their expiry")
    parser.add_argument("host", nargs="+", help="TLS hostnames to check")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--connect", help="connect to this IP while checking the supplied TLS hostname")
    parser.add_argument("--days", type=int, default=30, help="minimum remaining validity")
    parser.add_argument("--timeout", type=float, default=5, help="socket timeout in seconds")
    parser.add_argument("--ca-file", type=Path, help="add a private CA bundle")
    parser.add_argument("--cert-file", type=Path, help="compare the served leaf with the first PEM certificate")
    parser.add_argument("--json", action="store_true", help="output results as JSON")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.days < 0 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("Port must be 1–65535, days nonnegative, and timeout positive and finite.")

    try:
        if args.connect is not None:
            args.connect = str(ipaddress.ip_address(args.connect))
        context = ssl.create_default_context()
        if args.ca_file:
            context.load_verify_locations(cafile=str(args.ca_file))
        expected = file_fingerprint(args.cert_file) if args.cert_file else None
        results = [check_certificate(host, args, context, expected) for host in args.host]
    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for result in results:
            outcome = "OK" if result["ok"] else "FAIL"
            print(f"{outcome} {result['host']}:{result['port']}")
            if "expires_utc" in result:
                print(f"  Expires {result['expires_utc']} ({result['days_left']:.2f} days left)")
                print(f"  SHA-256 {result['sha256']}")
            for error in result["errors"]:
                print(f"  {error}")

    return int(any(not result["ok"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
