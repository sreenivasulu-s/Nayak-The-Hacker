import os
import subprocess
import sys


def test_cli_rejects_non_academy_target():
    result = subprocess.run(
        [sys.executable, "nayak", "lab", "https://example.com"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )
    assert result.returncode == 2
    assert "Only PortSwigger Web Security Academy training targets" in result.stderr


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "nayak", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )
    assert result.returncode == 0
    assert "PortSwigger" in result.stdout
