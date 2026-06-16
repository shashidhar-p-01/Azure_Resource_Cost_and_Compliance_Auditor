import json
from pathlib import Path
from typing import List

import pandas as pd

from auditor.models import Finding


def findings_to_dataframe(findings: List[Finding]) -> pd.DataFrame:
    rows = [
        {
            "resource_id": finding.resource_id,
            "resource_name": finding.resource_name,
            "check_name": finding.check_name,
            "severity": finding.severity.value,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "estimated_monthly_savings": finding.estimated_monthly_savings,
        }
        for finding in findings
    ]
    return pd.DataFrame(rows)


def generate_summary(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df.groupby(["severity", "check_name"], dropna=False)
        .agg(
            findings_count=("resource_id", "count"),
            total_estimated_monthly_savings=("estimated_monthly_savings", "sum"),
        )
        .reset_index()
    )


def export_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def export_excel(df: pd.DataFrame, summary_df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Findings")
        summary_df.to_excel(writer, index=False, sheet_name="Summary")


def export_json(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = df.to_dict(orient="records")
    with path.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=2)
