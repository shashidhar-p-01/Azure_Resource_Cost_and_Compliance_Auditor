import subprocess
import sys
from pathlib import Path


def test_cli_mock_run_all_exports_json(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_path = tmp_path / "audit-report"
    result = subprocess.run(
        [
            sys.executable,
            str(repo_root / "main.py"),
            "--mock",
            "--run-all",
            "--export",
            "json",
            "--output",
            str(output_path),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )
    assert output_path.with_suffix(".json").exists()
    assert "Exported findings to" in result.stdout


def test_cli_mock_list_rgs_prints_groups() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repo_root / "main.py"), "--mock", "--list-rgs"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )

    assert "demo-rg-1" in result.stdout
    assert "demo-rg-2" in result.stdout
