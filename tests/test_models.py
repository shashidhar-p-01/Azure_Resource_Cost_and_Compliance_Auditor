from auditor.models import Finding, Resource, Severity


def test_finding_equality():
    finding_a = Finding(
        resource_id="1",
        resource_name="test-resource",
        check_name="TestCheck",
        severity=Severity.LOW,
        description="desc",
        recommendation="rec",
        estimated_monthly_savings=0.0,
    )
    finding_b = Finding(
        resource_id="1",
        resource_name="test-resource",
        check_name="TestCheck",
        severity=Severity.LOW,
        description="desc",
        recommendation="rec",
        estimated_monthly_savings=0.0,
    )
    assert finding_a == finding_b


def test_severity_values():
    assert Severity.LOW.value == "Low"
    assert Severity.CRITICAL.value == "Critical"


def test_resource_tags_default_empty_dict():
    resource = Resource(id="1", name="test", type="test", location="westus")
    assert resource.tags == {}
    resource.tags["new"] = "value"
    assert Resource(id="2", name="other", type="test", location="eastus").tags == {}
