import os
import subprocess
import sys

import pytest

from system_repair.__main__ import main


def test_smoke_test_requires_explicit_demo(capsys):
    assert main(["--smoke-test"]) == 2
    assert "только вместе с --demo" in capsys.readouterr().err


def test_live_backend_is_rejected_on_non_windows(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    assert main([]) == 2
    assert "только в Windows" in capsys.readouterr().err


def test_version_does_not_initialize_windows(capsys):
    with pytest.raises(SystemExit) as exited:
        main(["--version"])
    assert exited.value.code == 0
    assert "0.2.0" in capsys.readouterr().out


def test_demo_entry_point_renders_scans_and_exits_without_backup(tmp_path):
    target = tmp_path / "not-created"
    result = subprocess.run(
        [sys.executable, "-m", "system_repair", "--demo", "--smoke-test", "--backup-dir", str(target)],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        capture_output=True, text=True, errors="replace", timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not target.exists()
