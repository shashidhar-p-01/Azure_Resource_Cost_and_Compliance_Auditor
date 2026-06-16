from typing import List, Optional

from auditor.checks.base_check import BaseCheck
from auditor.models import Finding, Resource, Severity

PRICE_TABLE = {
    "Standard_LRS": 0.04,
    "StandardSSD_LRS": 0.08,
    "Premium_LRS": 0.15,
    "UltraSSD_LRS": 0.125,
}


def _disk_monthly_savings(disk_size_gb: int, sku: str) -> float:
    price = PRICE_TABLE.get(sku, 0.05)
    return disk_size_gb * price


def _vm_downsize_savings(vm_size: Optional[str]) -> float:
    if not vm_size:
        return 50.0
    if vm_size.startswith("Standard_B"):
        return 30.0
    if vm_size.startswith("Standard_D2"):
        return 60.0
    if vm_size.startswith("Standard_D4"):
        return 120.0
    return 50.0


class UnattachedDiskCheck(BaseCheck):
    name: str = "Unattached Disk Check"

    def run(self, resources: List[Resource]) -> List[Finding]:
        findings: List[Finding] = []
        for disk in resources:
            if disk.properties.get("disk_state") != "Unattached":
                continue
            size_gb = disk.properties.get("size_gb", 0)
            sku = disk.properties.get("sku", "Unknown")
            severity = Severity.MEDIUM if size_gb < 128 else Severity.HIGH
            savings = _disk_monthly_savings(size_gb, sku)
            findings.append(
                Finding(
                    resource_id=disk.id,
                    resource_name=disk.name,
                    check_name=self.name,
                    severity=severity,
                    description=f"Disk {disk.name} is unattached ({sku}, {size_gb} GB).",
                    recommendation="Delete or snapshot the disk if it is no longer needed.",
                    estimated_monthly_savings=savings,
                )
            )
        return findings


class IdleVMCheck(BaseCheck):
    name: str = "Idle VM Check"

    def run(self, resources: List[Resource]) -> List[Finding]:
        findings: List[Finding] = []
        for vm in resources:
            if vm.properties.get("power_state") != "PowerState/running":
                continue
            average_cpu = self.azure_client.get_vm_cpu_metrics(vm.id, days=7)
            if average_cpu is None or average_cpu >= 5.0:
                continue
            savings = _vm_downsize_savings(vm.properties.get("vm_size"))
            findings.append(
                Finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    check_name=self.name,
                    severity=Severity.HIGH,
                    description=(
                        f"VM {vm.name} has low average CPU usage ({average_cpu:.1f}% over 7 days)."
                    ),
                    recommendation="Resize to a smaller VM size or deallocate if unused.",
                    estimated_monthly_savings=savings,
                )
            )
        return findings


class StoppedNotDeallocatedVMCheck(BaseCheck):
    name: str = "Stopped But Not Deallocated VM Check"

    def run(self, resources: List[Resource]) -> List[Finding]:
        findings: List[Finding] = []
        for vm in resources:
            if vm.properties.get("power_state") != "PowerState/stopped":
                continue
            savings = _vm_downsize_savings(vm.properties.get("vm_size"))
            findings.append(
                Finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    check_name=self.name,
                    severity=Severity.HIGH,
                    description=(
                        f"VM {vm.name} is stopped but not deallocated and still incurs charges."
                    ),
                    recommendation="Deallocate the VM to stop compute billing.",
                    estimated_monthly_savings=savings,
                )
            )
        return findings
