from typing import List

from auditor.checks.cost_checks import (
    IdleVMCheck,
    StoppedNotDeallocatedVMCheck,
    UnattachedDiskCheck,
)
from auditor.checks.security_checks import (
    MissingTagsCheck,
    OpenNSGPortCheck,
    PublicBlobStorageCheck,
    port_in_range,
)
from auditor.models import Resource, Severity


class DummyAzureClient:
    def __init__(self, resources: List[Resource]):
        self._resources = resources

    def list_disks(self):
        return [r for r in self._resources if r.type == "Microsoft.Compute/disks"]

    def list_virtual_machines(self):
        return [
            r for r in self._resources if r.type == "Microsoft.Compute/virtualMachines"
        ]

    def list_network_security_groups(self):
        return [
            r
            for r in self._resources
            if r.type == "Microsoft.Network/networkSecurityGroups"
        ]

    def list_storage_accounts(self):
        return [
            r for r in self._resources if r.type == "Microsoft.Storage/storageAccounts"
        ]

    def get_vm_cpu_metrics(self, vm_id: str, days: int = 7):
        vm = next((r for r in self._resources if r.id == vm_id), None)
        return vm.properties.get("average_cpu") if vm else None


def test_unattached_disk_check_flags_unattached_disk():
    resources = [
        Resource(
            id="disk-1",
            name="disk-unattached",
            type="Microsoft.Compute/disks",
            location="eastus",
            tags={},
            properties={
                "disk_state": "Unattached",
                "sku": "Standard_LRS",
                "size_gb": 100,
            },
        )
    ]
    check = UnattachedDiskCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].estimated_monthly_savings == 4.0


def test_unattached_disk_check_skips_attached_disk():
    resources = [
        Resource(
            id="disk-2",
            name="disk-attached",
            type="Microsoft.Compute/disks",
            location="eastus",
            tags={},
            properties={"disk_state": "Attached", "sku": "Standard_LRS", "size_gb": 50},
        )
    ]
    check = UnattachedDiskCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 0


def test_idle_vm_check_flags_low_cpu_vm():
    resources = [
        Resource(
            id="vm-1",
            name="idle-vm",
            type="Microsoft.Compute/virtualMachines",
            location="eastus",
            tags={},
            properties={
                "power_state": "PowerState/running",
                "vm_size": "Standard_B2s",
                "average_cpu": 2.0,
            },
        )
    ]
    check = IdleVMCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_stopped_not_deallocated_vm_check_flags_stopped_vm():
    resources = [
        Resource(
            id="vm-2",
            name="stopped-vm",
            type="Microsoft.Compute/virtualMachines",
            location="eastus",
            tags={},
            properties={
                "power_state": "PowerState/stopped",
                "vm_size": "Standard_D2s_v3",
            },
        )
    ]
    check = StoppedNotDeallocatedVMCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_open_nsg_port_check_flags_ssh():
    resources = [
        Resource(
            id="nsg-1",
            name="open-ssh-nsg",
            type="Microsoft.Network/networkSecurityGroups",
            location="eastus",
            tags={},
            properties={
                "security_rules": [
                    {
                        "name": "Allow-SSH-Internet",
                        "direction": "Inbound",
                        "access": "Allow",
                        "source_address_prefix": "*",
                        "destination_port_range": "22",
                    }
                ]
            },
        )
    ]
    check = OpenNSGPortCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_open_nsg_port_check_port_range():
    assert port_in_range(22, "20-30")
    assert not port_in_range(80, "20-30")
    assert port_in_range(22, "*")


def test_public_blob_storage_check_flags_public_storage():
    resources = [
        Resource(
            id="storage-1",
            name="publicstorage",
            type="Microsoft.Storage/storageAccounts",
            location="eastus",
            tags={},
            properties={"allow_blob_public_access": True},
        )
    ]
    check = PublicBlobStorageCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_missing_tags_check_flags_missing_tags():
    resources = [
        Resource(
            id="res-1",
            name="resource-1",
            type="Microsoft.Resources/resourceGroups",
            location="eastus",
            tags={"environment": "dev"},
            properties={},
        )
    ]
    check = MissingTagsCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_missing_tags_check_clean_resource():
    resources = [
        Resource(
            id="res-2",
            name="resource-2",
            type="Microsoft.Resources/resourceGroups",
            location="eastus",
            tags={
                "environment": "dev",
                "owner": "alice",
                "cost-centre": "team-a",
                "project": "audit-demo",
            },
            properties={},
        )
    ]
    check = MissingTagsCheck(azure_client=DummyAzureClient(resources))

    findings = check.run(resources)

    assert len(findings) == 0
