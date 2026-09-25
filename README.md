# SpineAPI

Defensive API security posture auditor.

It finds API endpoints, checks static rate-limit coverage, writes a report,
and generates defensive pytest stubs.

Requires Python 3.9+. No third-party packages.

---

## Setup

```bash
python3 --version
cd SpineAPI
```

Optional install (adds the `spineapi` command):

```bash
pip install -e .
```

Or run without installing:

```bash
python3 -m spineapi --help
```

---

## Quick start (sample app)

```bash
python3 -m spineapi report \
  --source-code fixtures/sample_app \
  --swagger fixtures/openapi.json \
  -o api-security-report
```

Open:

- `api-security-report/security-posture.md`
- `api-security-report/test_api_security_defensive.py`

---

## Run against your API

### Full report + defensive tests

```bash
python3 -m spineapi report \
  --source-code /path/to/your/backend \
  --swagger /path/to/openapi.json \
  -o api-security-report
```

### Discover only

```bash
python3 -m spineapi discover \
  --source-code /path/to/your/backend \
  --swagger /path/to/openapi.json \
  -o api-security-report
```

### Analyze only

```bash
python3 -m spineapi analyze \
  --source-code /path/to/your/backend \
  -o api-security-report
```

### Generate tests only

```bash
python3 -m spineapi generate-tests \
  --source-code /path/to/your/backend \
  -o api-security-report
```

---

## Flags

| Flag | Meaning |
|---|---|
| `--source-code PATH` | Backend root |
| `--swagger PATH` | OpenAPI/Swagger **JSON** |
| `-o PATH` | Output folder |
| `--no-integrations` | Skip partners/payments/KYC catalogs |
| `--no-source` | Skip source route scan |
| `--tests-out PATH` | Custom path for generated tests |

YAML OpenAPI is not supported. Convert to JSON first.

---

## Project layout

```
spineapi/
  models.py       # data models
  catalogs.py     # partners / payments / KYC catalogs
  discovery.py    # OpenAPI + Django/Flask discovery
  analyzer.py     # static rate-limit analysis
  reporter.py     # JSON / Markdown reports
  testgen.py      # defensive pytest generator
  audit.py        # orchestration
  cli.py          # command line
```

---

## Output

| File | Purpose |
|---|---|
| `security-posture.md` | Human-readable report |
| `security-posture.json` | Machine-readable report |
| `test_api_security_defensive.py` | Pytest stubs |

---

## Using generated tests

1. Copy the generated file into your test suite
2. Implement the `api_client` fixture
3. Run `pytest test_api_security_defensive.py`

These tests assert safe behavior. They do not run attack traffic.

---

## Out of scope

- Brute force
- DDoS / flood simulation
- Live attack scripts

For authorized load or scanning, use k6, Locust, OWASP ZAP, or Burp Suite.
