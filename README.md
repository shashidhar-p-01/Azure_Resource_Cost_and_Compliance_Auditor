# Azure Resource Cost & Compliance Auditor

A command-line audit tool for Azure subscriptions that detects cost waste and security misconfigurations. It supports real Azure authentication and a mock mode that runs entirely from local fixtures.

![CI](https://github.com/shashidhar-p-01/Azure_Resource_Cost_and_Compliance_Auditor/actions/workflows/ci.yml/badge.svg)

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py --mock --run-all --export csv --output ./report/audit-report
```

## Features

- Mock mode for instant evaluation without Azure credentials
- Cost checks for unattached disks, idle VMs, and stopped-but-not-deallocated VMs
- Security checks for open NSG ports, public blob storage, and missing required tags
- Export findings as CSV, Excel, or JSON
- Rich CLI output with color-coded severity levels

## Files

- `main.py` — thin entrypoint that calls `auditor.cli.main`
- `auditor/azure_client.py` — Azure SDK wrapper with real and mock modes
- `auditor/models.py` — `Severity`, `Resource`, and `Finding` dataclasses
- `auditor/report.py` — pandas-based report generation and exports
- `auditor/cli.py` — argument parsing, orchestration, and rich output
- `auditor/checks/` — audit check implementations
- `fixtures/sample_resources.json` — realistic mock Azure resource data
- `tests/` — unit tests using mock data and dependency-free checks
- `.github/workflows/ci.yml` — CI for lint and tests

## Mock mode

Mock mode uses fixture data from `fixtures/sample_resources.json`:

- 2 resource groups
- 3 disks (2 unattached)
- 3 VMs (idle, stopped but not deallocated, healthy)
- 2 NSGs (one open SSH, one clean)
- 2 storage accounts (one public, one private)

Run:

```bash
python main.py --mock --run-all
```

## Real Azure setup

Create a service principal and save credentials in `.env`:

```env
CLIENT_ID=...
CLIENT_SECRET=...
TENANT_ID=...
SUBSCRIPTION_ID=...
```

Then run:

```bash
python main.py --run-all --export xlsx --output ./report/azure-audit
```

## Checks implemented

| Check | Category | Severity | What it detects |
|---|---|---|---|
| `Unattached Disk Check` | Cost | MEDIUM / HIGH | Disks not attached to any VM |
| `Idle VM Check` | Cost | HIGH | Running VMs with very low CPU usage |
| `Stopped But Not Deallocated VM Check` | Cost | HIGH | Stopped VMs still incurring compute charges |
| `Open NSG Port Check` | Security | CRITICAL / HIGH | Publicly exposed management or database ports |
| `Public Blob Storage Check` | Security | HIGH | Storage accounts with public blob access |
| `Missing Required Tags Check` | Security | LOW / MEDIUM | Resources missing required tags |

## CLI reference

```bash
python main.py --mock --run-all
python main.py --mock --checks UnattachedDiskCheck,PublicBlobStorageCheck
python main.py --mock --checks cost --export xlsx --output ./report/audit
python main.py --list-rgs --mock
```

## Architecture

1. `AzureClient` loads credentials or fixture data
2. `cli.py` builds resource lists and runs selected checks
3. Each check returns `Finding` objects
4. `report.py` converts findings to DataFrame and exports them

## Tests

Run tests with:

```bash
pytest tests/
```

## Contributing

To add a new check:

1. Add a subclass of `BaseCheck` in `auditor/checks/`
2. Add the new class to `auditor/cli.py` `CHECK_REGISTRY`
3. Add unit tests in `tests/test_checks.py`
