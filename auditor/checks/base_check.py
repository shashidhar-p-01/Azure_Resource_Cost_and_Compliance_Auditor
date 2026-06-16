# import the abstract base class helper and decorator for abstract methods
from abc import ABC, abstractmethod

# import the Finding model type used by audit check results
from auditor.models import Finding, Resource, Severity


# base class for all audit checks, requiring a run() implementation
class BaseCheck(ABC):
    name: str = "BaseCheck"

    # constructor receives the Azure client and stores it for use in checks
    def __init__(self, azure_client):
        self.azure_client = azure_client

    @abstractmethod
    # each subclass must implement run() to inspect resources and return findings
    def run(self, resources: list[Resource]) -> list[Finding]:
        raise NotImplementedError("Subclasses must implement run()")


# throwaway test subclass to validate pipeline end-to-end
class AlwaysFlagCheck(BaseCheck):
    # give the test check a CLI display name
    name: str = "AlwaysFlagCheck"

    # run returns a finding for every resource passed in
    def run(self, resources: list[Resource]) -> list[Finding]:
        return [
            Finding(
                resource_id=resource.id,
                resource_name=resource.name,
                check_name=self.name,
                severity=Severity.LOW,
                description="This test check always flags the resource.",
                recommendation="No real remediation required; used for testing.",
                estimated_monthly_savings=0.0,
            )
            for resource in resources
        ]
