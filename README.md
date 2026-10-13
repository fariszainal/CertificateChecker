# Certificate Expiry Checker

A small command-line tool that checks TLS certificates for expiry. It connects to
`host:port` endpoints (or reads local PEM files), reports how many days are left,
flags each certificate by urgency, and can write CSV or JSON reports.

Useful as a quick first look at certificate visibility, for example during a
discovery call or a proof of concept, before moving to a full certificate
lifecycle management platform.

## What it reports

| Field | Meaning |
|---|---|
| `status` | `OK`, `WARNING`, `CRITICAL`, `EXPIRED` or `ERROR` (unreachable / not TLS) |
| `days_left` | Calendar days until expiry (negative if already expired) |
| `not_after` | Expiry date |
| `subject`, `issuer` | Certificate subject and issuer |
| `key` | Public key type and size (for example `RSA-2048`, `EC-secp256r1`) |
| `sig_hash` | Signature hash algorithm |
| `san_count` | Number of DNS names in the Subject Alternative Name extension |
| `sha256` | SHA-256 fingerprint |

Default thresholds: `WARNING` at 30 days or fewer, `CRITICAL` at 14 days or fewer.
Both can be changed.

## Install

Requires Python 3.9+.

```
pip install -r requirements.txt
```

## Usage

```
# Check one or more endpoints (port defaults to 443)
python cert_expiry_checker.py -t github.com -t example.com:443

# Read targets from a file, with custom thresholds
python cert_expiry_checker.py -f targets.example.txt --warn 45 --critical 14

# Check local PEM files and write reports
python cert_expiry_checker.py -p "./certs/*.pem" --csv report.csv --json report.json
```

Example output:

```
STATUS     DAYS  EXPIRES     KEY          SOURCE
------------------------------------------------------------------------------
EXPIRED      -3  2026-10-04  RSA-2048     127.0.0.1:8444
CRITICAL      5  2026-10-12  RSA-2048     127.0.0.1:8443
WARNING      20  2026-10-27  EC-secp256r1 127.0.0.1:8442
ERROR         -                           127.0.0.1:8499
          ConnectionRefusedError: [Errno 111] Connection refused
OK          200  2027-04-25  RSA-2048     127.0.0.1:8441
```

## Exit codes

Handy for cron jobs, CI and monitoring:

| Code | Meaning |
|---|---|
| 0 | All certificates OK |
| 1 | At least one WARNING |
| 2 | At least one CRITICAL or EXPIRED |
| 3 | At least one endpoint could not be checked |

## Design notes

- **Certificate verification is deliberately off.** The tool inspects whatever
  certificate a server presents, even if it is expired, self-signed or untrusted.
  It reports on certificates; it does not make trust decisions.
- Endpoints are checked in parallel (16 threads).

## Limitations

- It only sees certificates on servers it can reach. It is not a full discovery tool:
  it does not scan networks, cloud accounts or key stores.
- It does not validate certificate chains, check revocation (OCSP/CRL) or query
  Certificate Transparency logs.
- It reads the first (leaf) certificate a server presents and does not report intermediates.
- It reports only. It does not renew anything.

## Ideas for next steps

- Chain validation and revocation checks
- Certificate Transparency monitoring
- Create tickets for critical certificates through an ITSM API such as ServiceNow
- Scheduled runs

## License

MIT. See [LICENSE](LICENSE).
