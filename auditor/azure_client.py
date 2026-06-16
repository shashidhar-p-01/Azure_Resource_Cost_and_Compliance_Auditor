import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from dotenv import load_dotenv

from auditor.models import Resource


class AzureAuthError(Exception):
    """Raised when Azure authentication or authorization fails."""


class AzureClient:
    """Azure SDK wrapper that supports real and mock modes."""

    def __init__(self, mock: bool = False) -> None:
        self.mock = mock
        self.subscription_id = None
        self._fixtures: Dict[str, Any] = {}
        self.credential = None
        self._resource_client = None
        self._compute_client = None
        self._network_client = None
        self._storage_client = None
        self._monitor_client = None

        if self.mock:
            self._load_fixture_data()
            self.subscription_id = "mock-subscription"
        else:
            self._load_environment()
            self._authenticate()
            self._build_clients()

    def _load_environment(self) -> None:
        load_dotenv()
        self.tenant_id = os.getenv("TENANT_ID")
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.subscription_id = os.getenv("SUBSCRIPTION_ID")

        if not all(
            [self.tenant_id, self.client_id, self.client_secret, self.subscription_id]
        ):
            raise AzureAuthError(
                "Missing Azure credentials. Make sure CLIENT_ID, CLIENT_SECRET, TENANT_ID, and SUBSCRIPTION_ID are set in .env."
            )

    def _authenticate(self) -> None:
        try:
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        except AzureError as exc:
            raise AzureAuthError("Failed to authenticate to Azure.") from exc

    def _build_clients(self) -> None:
        self._resource_client = ResourceManagementClient(
            self.credential, self.subscription_id
        )
        self._compute_client = ComputeManagementClient(
            self.credential, self.subscription_id
        )
        self._network_client = NetworkManagementClient(
            self.credential, self.subscription_id
        )
        self._storage_client = StorageManagementClient(
            self.credential, self.subscription_id
        )
        self._monitor_client = MonitorManagementClient(
            self.credential, self.subscription_id
        )

    def _load_fixture_data(self) -> None:
        fixture_path = (
            Path(__file__).resolve().parents[1] / "fixtures" / "sample_resources.json"
        )
        if not fixture_path.exists():
            raise AzureAuthError(f"Mock fixture file not found: {fixture_path}")

        with fixture_path.open("r", encoding="utf-8") as fixture_file:
            self._fixtures = json.load(fixture_file)

    def _normalize_resource(self, resource_dict: Dict[str, Any]) -> Resource:
        return Resource(
            id=resource_dict["id"],
            name=resource_dict["name"],
            type=resource_dict["type"],
            location=resource_dict.get("location", ""),
            tags=resource_dict.get("tags", {}),
            properties=resource_dict.get("properties", {}),
        )

    def list_resource_groups(self) -> List[Resource]:
        if self.mock:
            return [
                self._normalize_resource(item)
                for item in self._fixtures.get("resource_groups", [])
            ]

        groups = self._resource_client.resource_groups.list()
        return [
            Resource(
                id=group.id,
                name=group.name,
                type="Microsoft.Resources/resourceGroups",
                location=group.location,
                tags=group.tags or {},
                properties={},
            )
            for group in groups
        ]

    def list_disks(self) -> List[Resource]:
        if self.mock:
            return [
                self._normalize_resource(item)
                for item in self._fixtures.get("disks", [])
            ]

        disks = self._compute_client.disks.list()
        return [
            Resource(
                id=disk.id,
                name=disk.name,
                type="Microsoft.Compute/disks",
                location=disk.location,
                tags=disk.tags or {},
                properties={
                    "disk_state": disk.disk_state,
                    "sku": disk.sku.name if disk.sku else None,
                    "size_gb": disk.disk_size_gb,
                },
            )
            for disk in disks
        ]

    def list_virtual_machines(self) -> List[Resource]:
        if self.mock:
            return [
                self._normalize_resource(item)
                for item in self._fixtures.get("virtual_machines", [])
            ]

        vms = self._compute_client.virtual_machines.list_all()
        normalized: List[Resource] = []
        for vm in vms:
            vm_properties = {
                "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                "power_state": None,
                "os_type": (
                    vm.storage_profile.os_disk.os_type.name
                    if vm.storage_profile
                    and vm.storage_profile.os_disk
                    and vm.storage_profile.os_disk.os_type
                    else None
                ),
            }
            try:
                rg = vm.id.split("/resourceGroups/")[1].split("/")[0]
                instance_view = self._compute_client.virtual_machines.instance_view(
                    rg, vm.name
                )
                for status in instance_view.statuses or []:
                    if status.code and status.code.startswith("PowerState/"):
                        vm_properties["power_state"] = status.code
                        break
            except Exception:
                pass

            normalized.append(
                Resource(
                    id=vm.id,
                    name=vm.name,
                    type=vm.type,
                    location=vm.location or "",
                    tags=vm.tags or {},
                    properties=vm_properties,
                )
            )
        return normalized

    def list_network_security_groups(self) -> List[Resource]:
        if self.mock:
            return [
                self._normalize_resource(item)
                for item in self._fixtures.get("network_security_groups", [])
            ]

        nsgs = self._network_client.network_security_groups.list_all()
        results: List[Resource] = []
        for nsg in nsgs:
            rules = []
            for rule in nsg.security_rules or []:
                rules.append(
                    {
                        "name": rule.name,
                        "direction": rule.direction,
                        "access": rule.access,
                        "source_address_prefix": getattr(
                            rule, "source_address_prefix", None
                        ),
                        "source_address_prefixes": getattr(
                            rule, "source_address_prefixes", []
                        ),
                        "destination_port_range": getattr(
                            rule, "destination_port_range", None
                        ),
                        "destination_port_ranges": getattr(
                            rule, "destination_port_ranges", []
                        ),
                    }
                )
            results.append(
                Resource(
                    id=nsg.id,
                    name=nsg.name,
                    type=nsg.type,
                    location=nsg.location or "",
                    tags=nsg.tags or {},
                    properties={"security_rules": rules},
                )
            )
        return results

    def list_storage_accounts(self) -> List[Resource]:
        if self.mock:
            return [
                self._normalize_resource(item)
                for item in self._fixtures.get("storage_accounts", [])
            ]

        accounts = self._storage_client.storage_accounts.list()
        return [
            Resource(
                id=account.id,
                name=account.name,
                type=account.type,
                location=account.location or "",
                tags=account.tags or {},
                properties={
                    "allow_blob_public_access": getattr(
                        account, "allow_blob_public_access", False
                    ),
                    "primary_endpoints": getattr(account, "primary_endpoints", {}),
                },
            )
            for account in accounts
        ]

    def get_vm_cpu_metrics(self, vm_id: str, days: int = 7) -> Optional[float]:
        if self.mock:
            vm_data = next(
                (
                    item
                    for item in self._fixtures.get("virtual_machines", [])
                    if item["id"] == vm_id
                ),
                None,
            )
            if vm_data:
                return vm_data.get("properties", {}).get("average_cpu")
            return None

        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            timespan = f"{start_time.isoformat()}Z/{end_time.isoformat()}Z"
            metrics = self._monitor_client.metrics.list(
                resource_uri=vm_id,
                timespan=timespan,
                interval="PT1H",
                metricnames="Percentage CPU",
                aggregation="Average",
            )
            for metric in metrics.value:
                if metric.name.value == "Percentage CPU":
                    samples = [
                        data.average
                        for series in metric.timeseries
                        for data in series.data
                        if data.average is not None
                    ]
                    if not samples:
                        return None
                    return sum(samples) / len(samples)
            return None
        except AzureError:
            return None
