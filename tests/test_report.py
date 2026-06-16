import json
from pathlib import Path

from auditor.models import Finding, Severity
from auditor.report import (
    export_csv,
    export_excel,
    export_json,
    findings_to_dataframe,
    generate_summary,
)


def _sample_findings():
    return [
        Finding(
            resource_id="1",
            resource_name="resource-1",
            check_name="TestCheck",
            severity=Severity.LOW,
            description="desc",
            recommendation="rec",
            estimated_monthly_savings=10.0,
        ),
        Finding(
            resource_id="2",
            resource_name="resource-2",
            check_name="TestCheck",
            severity=Severity.HIGH,
            description="desc2",
            recommendation="rec2",
            estimated_monthly_savings=20.0,
        ),
    ]


def test_findings_to_dataframe():
    df = findings_to_dataframe(_sample_findings())

    assert list(df.columns) == [
        "resource_id",
        "resource_name",
        "check_name",
        "severity",
        "description",
        "recommendation",
        "estimated_monthly_savings",
    ]
    assert len(df) == 2


def test_generate_summary():
    df = findings_to_dataframe(_sample_findings())
    summary = generate_summary(df)

    assert "severity" in summary.columns
    assert "check_name" in summary.columns
    assert summary["findings_count"].sum() == 2
    assert summary["total_estimated_monthly_savings"].sum() == 30.0


def test_exports_write_files(tmp_path: Path):
    df = findings_to_dataframe(_sample_findings())
    summary = generate_summary(df)

    csv_path = tmp_path / "report.csv"
    export_csv(df, csv_path)
    assert csv_path.exists()

    xlsx_path = tmp_path / "report.xlsx"
    export_excel(df, summary, xlsx_path)
    assert xlsx_path.exists()

    json_path = tmp_path / "report.json"
    export_json(df, json_path)
    assert json_path.exists()

    with json_path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    assert isinstance(data, list)
    assert len(data) == 2
