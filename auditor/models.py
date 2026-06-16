from dataclasses import dataclass, field
from enum import Enum


# define severity levels for findings produced by checks
class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# data model representing a single audit finding
@dataclass
class Finding:
    resource_id: str
    resource_name: str
    check_name: str
    severity: Severity
    description: str
    recommendation: str
    estimated_monthly_savings: float = 0.0


# data model representing a resource to audit
@dataclass
class Resource:
    id: str
    name: str
    type: str
    location: str
    tags: dict = field(default_factory=dict)
    properties: dict = field(default_factory=dict)
