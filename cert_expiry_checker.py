#!/usr/bin/env python3
"""
Certificate Expiry Checker
--------------------------
Scans TLS endpoints (host:port) and/or local PEM files, reports days until
expiry, flags certificates by urgency, and writes CSV/JSON for reporting or
for feeding a ticketing / CLM workflow (e.g. ServiceNow).

Usage examples:
  python cert_expiry_checker.py -t example.com:443 -t github.com
  python cert_expiry_checker.py -f targets.txt --warn 45 --critical 14
  python cert_expiry_checker.py -p ./certs/*.pem --json report.json --csv report.csv

Exit codes (handy for cron / CI / monitoring):
  0 = all OK, 1 = at least one WARNING, 2 = at least one CRITICAL/EXPIRED,
  3 = at least one endpoint could not be checked

Requires: Python 3.9+ and `pip install cryptography`
"""
import argparse
import csv
import glob
import json
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DEFAULT_PORT = 443


def key_info(cert):
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}"
    return type(pub).__name__


def describe(cert, source, warn, critical):
    """Turn an x509 certificate into a flat report record."""
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    days = (not_after.date() - now.date()).days
    if now > not_after:
        status = "EXPIRED"
    elif days <= critical:
        status = "CRITICAL"
    elif days <= warn:
        status = "WARNING"
    else:
        status = "OK"
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "source": source,
        "status": status,
        "days_left": days,
        "not_after": not_after.strftime("%Y-%m-%d"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "key": key_info(cert),
        "sig_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a",
        "san_count": len(sans),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "error": "",
    }


def error_record(source, msg):
    return {"source": source, "status": "ERROR", "days_left": "", "not_after": "",
            "subject": "", "issuer": "", "key": "", "sig_hash": "",
            "san_count": "", "sha256": "", "error": msg}


def check_endpoint(target, warn, critical, timeout):
    host, _, port = target.partition(":")
    port = int(port) if port else DEFAULT_PORT
    # Verification is deliberately OFF: we want to *inspect* the certificate
    # even if it is expired, self-signed or untrusted. This tool reports on
    # certificates; it does not make trust decisions.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        return describe(cert, f"{host}:{port}", warn, critical)
    except Exception as exc:  # network, TLS, parse errors
        return error_record(f"{host}:{port}", f"{type(exc).__name__}: {exc}")


def check_pem(path, warn, critical):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        cert = x509.load_pem_x509_certificate(data)
        return describe(cert, path, warn, critical)
    except Exception as exc:
        return error_record(path, f"{type(exc).__name__}: {exc}")


def read_targets_file(path):
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def print_table(rows):
    order = {"EXPIRED": 0, "CRITICAL": 1, "WARNING": 2, "ERROR": 3, "OK": 4}
    rows = sorted(rows, key=lambda r: (order[r["status"]],
                                       r["days_left"] if r["days_left"] != "" else 0))
    print(f"{'STATUS':<9} {'DAYS':>5}  {'EXPIRES':<11} {'KEY':<12} SOURCE")
    print("-" * 78)
    for r in rows:
        days = r["days_left"] if r["days_left"] != "" else "-"
        print(f"{r['status']:<9} {days:>5}  {r['not_after']:<11} {r['key']:<12} {r['source']}")
        if r["error"]:
            print(f"{'':>9} {r['error']}")


def main():
    ap = argparse.ArgumentParser(description="Certificate expiry checker")
    ap.add_argument("-t", "--target", action="append", default=[],
                    help="host[:port] to check (repeatable)")
    ap.add_argument("-f", "--file", help="text file with one host[:port] per line")
    ap.add_argument("-p", "--pem", nargs="*", default=[], help="PEM file(s) or globs")
    ap.add_argument("--warn", type=int, default=30, help="warning threshold in days (default 30)")
    ap.add_argument("--critical", type=int, default=14, help="critical threshold in days (default 14)")
    ap.add_argument("--timeout", type=float, default=5.0, help="connect timeout seconds")
    ap.add_argument("--csv", help="write CSV report to this path")
    ap.add_argument("--json", help="write JSON report to this path")
    args = ap.parse_args()

    targets = list(args.target)
    if args.file:
        targets += read_targets_file(args.file)
    pems = [p for pat in args.pem for p in glob.glob(pat)]
    if not targets and not pems:
        ap.error("nothing to check: use -t, -f or -p")

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(check_endpoint, t, args.warn, args.critical, args.timeout)
                   for t in targets]
        rows = [f.result() for f in futures]
    rows += [check_pem(p, args.warn, args.critical) for p in pems]

    print_table(rows)

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"generated": datetime.now(timezone.utc).isoformat(),
                       "warn_days": args.warn, "critical_days": args.critical,
                       "results": rows}, fh, indent=2)

    statuses = {r["status"] for r in rows}
    if statuses & {"EXPIRED", "CRITICAL"}:
        sys.exit(2)
    if "ERROR" in statuses:
        sys.exit(3)
    if "WARNING" in statuses:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
