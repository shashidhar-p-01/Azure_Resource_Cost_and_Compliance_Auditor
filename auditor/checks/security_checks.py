import re
from typing import List

from auditor.checks.base_check import BaseCheck
from auditor.models import Finding, Resource, Severity


def port_in_range(port: int, port_range_str: str) -> bool:
    if port_range_str == "*":
        return True
    if "-" in port_range_str:
        start, end = port_range_str.split("-", 1)
        try:
            return int(start) <= port <= int(end)
        except ValueError:
            return False
    try:
        return int(port_range_str) == port
    except ValueError:
        return False


def _is_open_source(address: str) -> bool:
    return address in {"*", "0.0.0.0/0", "Internet", "Any"}


def _severity_for_port(port: int) -> Severity:
    return Severity.CRITICAL if port in {22, 3389} else Severity.HIGH


class OpenNSGPortCheck(BaseCheck):
    name: str = "Open NSG Port Check"

    def run(self, resources: List[Resource]) -> List[Finding]:
        findings: List[Finding] = []
        target_ports = {22, 3389, 1433, 5432, 27017, 6379}

        for nsg in resources:
            for rule in nsg.properties.get("security_rules", []):
                if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
                    continue

                sources = [rule.get("source_address_prefix", "")]
                sources.extend(rule.get("source_address_prefixes", []))
                if not any(
                    _is_open_source(str(source)) for source in sources if source
                ):
                    continue

                port_ranges = [rule.get("destination_port_range")]
                port_ranges.extend(rule.get("destination_port_ranges", []))
                for port_range in (pr for pr in port_ranges if pr):
                    for port in target_ports:
                        if port_in_range(port, port_range):
                            findings.append(
                                Finding(
                                    resource_id=nsg.id,
                                    resource_name=nsg.name,
                                    check_name=self.name,
                                    severity=_severity_for_port(port),
                                    description=(
                                        f"NSG {nsg.name} allows inbound port {port} from {port_range}."
                                    ),
                                    recommendation=(
                                        "Restrict source addresses to known ranges or use Azure Bastion/JIT access."
                                    ),
                                    estimated_monthly_savings=0.0,
                                )
                            )
                            break
                    else:
                        continue
                    break
        return findings


class PublicBlobStorageCheck(BaseCheck):
    name: str = "Public Blob Storage Check"

    def run(self, resources: List[Resource]) -> List[Finding]:
        findings: List[Finding] = []
        for account in resources:
            if account.properties.get("allow_blob_public_access"):
                findings.append(
                    Finding(
                        resource_id=account.id,
                        resource_name=account.name,
                        check_name=self.name,
                        severity=Severity.HIGH,
                        description=(
                            f"Storage account {account.name} has public blob access enabled."
                        ),
                        recommendation=(
                            "Disable public blob access unless explicitly required."
                        ),
                        estimated_monthly_savings=0.0,
                    )
                )
        return findings


class MissingTagsCheck(BaseCheck):
    name: str = "Missing Required Tags Check"

    def run(self, resources: List[Resource]) -> List[Finding]:
        findings: List[Finding] = []
        required_tags = ["environment", "owner", "cost-centre", "project"]
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")

        for resource in resources:
            missing = [tag for tag in required_tags if not resource.tags.get(tag)]
            invalid = [
                tag
                for tag, value in resource.tags.items()
                if value and not pattern.match(value)
            ]
            if not missing and not invalid:
                continue

            severity = Severity.LOW if len(missing) <= 2 else Severity.MEDIUM
            description = (
                f"Resource {resource.name} is missing tags: {', '.join(missing)}."
                if missing
                else f"Resource {resource.name} has invalid tag values: {', '.join(invalid)}."
            )
            findings.append(
                Finding(
                    resource_id=resource.id,
                    resource_name=resource.name,
                    check_name=self.name,
                    severity=severity,
                    description=description,
                    recommendation=(
                        "Add or correct required tags: environment, owner, cost-centre, project."
                    ),
                    estimated_monthly_savings=0.0,
                )
            )

        return findings
