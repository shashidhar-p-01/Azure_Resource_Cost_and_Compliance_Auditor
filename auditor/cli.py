import argparse
import logging
from pathlib import Path
from typing import Dict, List, Type

from rich.console import Console
from rich.table import Table

from auditor.azure_client import AzureAuthError, AzureClient
from auditor.checks.base_check import AlwaysFlagCheck, BaseCheck
from auditor.checks.cost_checks import (
    IdleVMCheck,
    StoppedNotDeallocatedVMCheck,
    UnattachedDiskCheck,
)
from auditor.checks.security_checks import (
    MissingTagsCheck,
    OpenNSGPortCheck,
    PublicBlobStorageCheck,
)
from auditor.models import Finding, Resource
from auditor.report import (
    export_csv,
    export_excel,
    export_json,
    findings_to_dataframe,
    generate_summary,
)

CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {
    "AlwaysFlagCheck": AlwaysFlagCheck,
    "UnattachedDiskCheck": UnattachedDiskCheck,
    "IdleVMCheck": IdleVMCheck,
    "StoppedNotDeallocatedVMCheck": StoppedNotDeallocatedVMCheck,
    "OpenNSGPortCheck": OpenNSGPortCheck,
    "PublicBlobStorageCheck": PublicBlobStorageCheck,
    "MissingTagsCheck": MissingTagsCheck,
}

CHECK_CATEGORIES: Dict[str, List[str]] = {
    "cost": [
        "UnattachedDiskCheck",
        "IdleVMCheck",
        "StoppedNotDeallocatedVMCheck",
    ],
    "security": [
        "OpenNSGPortCheck",
        "PublicBlobStorageCheck",
        "MissingTagsCheck",
    ],
    "all": list(CHECK_REGISTRY.keys()),
}

CONSOLE = Console()


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler("audit.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Azure Resource Cost & Compliance Auditor"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run in mock mode using fixture data",
    )
    parser.add_argument(
        "--list-rgs",
        action="store_true",
        help="List resource groups and exit",
    )
    parser.add_argument(
        "--run-all",
        action="store_true",
        help="Run all available checks",
    )
    parser.add_argument(
        "--checks",
        type=str,
        help=(
            "Comma-separated list of check names or categories to run, "
            "e.g. cost,security or UnattachedDiskCheck,OpenNSGPortCheck"
        ),
    )
    parser.add_argument(
        "--export",
        choices=["csv", "xlsx", "json"],
        help="Export findings in the specified format",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./report",
        help="Output path prefix for exported files",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days for VM CPU metrics in IdleVMCheck",
    )
    return parser.parse_args()


def _print_resource_groups(resource_groups: List[Dict[str, str]]) -> None:
    table = Table(title="Resource Groups")
    table.add_column("Name", style="cyan")
    table.add_column("Location", style="green")
    table.add_column("ID", style="magenta")

    for rg in resource_groups:
        table.add_row(rg["name"], rg["location"], rg["id"])

    CONSOLE.print(table)


def _print_findings(findings: List[Finding]) -> None:
    table = Table(title="Audit Findings")
    table.add_column("Resource", style="cyan")
    table.add_column("Check", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Description", style="yellow")
    table.add_column("Recommendation", style="green")
    table.add_column("Savings", style="magenta")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "yellow",
        "MEDIUM": "bright_blue",
        "LOW": "blue",
    }

    for finding in findings:
        severity_name = finding.severity.name
        color = severity_colors.get(severity_name, "white")
        table.add_row(
            finding.resource_name,
            finding.check_name,
            f"[{color}]{severity_name}[/{color}]",
            finding.description,
            finding.recommendation,
            f"${finding.estimated_monthly_savings:.2f}",
        )

    CONSOLE.print(table)


def _normalize_check_names(raw_checks: str) -> List[str]:
    selected: List[str] = []
    for token in raw_checks.split(","):
        normalized = token.strip()
        if not normalized:
            continue
        if normalized.lower() in CHECK_CATEGORIES:
            selected.extend(CHECK_CATEGORIES[normalized.lower()])
        else:
            selected.append(normalized)
    return selected


def _build_resources(azure_client: AzureClient) -> Dict[str, List[Resource]]:
    resource_groups = azure_client.list_resource_groups()
    disks = azure_client.list_disks()
    vms = azure_client.list_virtual_machines()
    nsgs = azure_client.list_network_security_groups()
    storage_accounts = azure_client.list_storage_accounts()
    return {
        "resource_groups": resource_groups,
        "disks": disks,
        "vms": vms,
        "nsgs": nsgs,
        "storage_accounts": storage_accounts,
        "all": [*resource_groups, *disks, *vms, *nsgs, *storage_accounts],
    }


def _resources_for_check(
    check: BaseCheck, resources: Dict[str, List[Resource]]
) -> List[Resource]:
    if isinstance(check, UnattachedDiskCheck):
        return resources["disks"]
    if isinstance(check, IdleVMCheck):
        return resources["vms"]
    if isinstance(check, StoppedNotDeallocatedVMCheck):
        return resources["vms"]
    if isinstance(check, OpenNSGPortCheck):
        return resources["nsgs"]
    if isinstance(check, PublicBlobStorageCheck):
        return resources["storage_accounts"]
    if isinstance(check, MissingTagsCheck):
        return resources["all"]
    if isinstance(check, AlwaysFlagCheck):
        return resources["resource_groups"]
    return resources["all"]


def _print_summary(findings: List[Finding]) -> None:
    total_savings = sum(f.estimated_monthly_savings for f in findings)
    total_findings = len(findings)
    CONSOLE.print(f"[bold]Total findings:[/] {total_findings}")
    CONSOLE.print(f"[bold]Estimated monthly savings:[/] ${total_savings:.2f}")


def main() -> None:
    _configure_logging()
    args = _parse_args()

    try:
        azure_client = AzureClient(mock=args.mock)
    except AzureAuthError as exc:
        logging.error(str(exc))
        raise

    if args.list_rgs:
        resource_groups = azure_client.list_resource_groups()
        _print_resource_groups(
            [
                {"name": rg.name, "location": rg.location, "id": rg.id}
                for rg in resource_groups
            ]
        )
        return

    if not args.run_all and not args.checks:
        raise ValueError("Provide --run-all or --checks to execute checks.")

    selected_names = (
        CHECK_CATEGORIES["all"] if args.run_all else _normalize_check_names(args.checks)
    )
    selected_checks = [
        CHECK_REGISTRY[name](azure_client=azure_client) for name in selected_names
    ]

    resources = _build_resources(azure_client)
    findings: List[Finding] = []
    for check in selected_checks:
        findings.extend(check.run(_resources_for_check(check, resources)))

    _print_findings(findings)
    _print_summary(findings)

    df = findings_to_dataframe(findings)
    summary_df = generate_summary(df)

    if args.export:
        output_prefix = Path(args.output)
        if args.export == "csv":
            export_csv(df, output_prefix.with_suffix(".csv"))
        elif args.export == "xlsx":
            export_excel(df, summary_df, output_prefix.with_suffix(".xlsx"))
        elif args.export == "json":
            export_json(df, output_prefix.with_suffix(".json"))
        CONSOLE.print(
            f"Exported findings to {output_prefix.with_suffix('.' + args.export)}"
        )


if __name__ == "__main__":
    main()
