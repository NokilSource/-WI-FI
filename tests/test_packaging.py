import json
import zipfile
from pathlib import Path

from scripts.collect_licenses import collect as collect_licenses
from scripts.collect_source import collect as collect_source


def test_distribution_includes_full_license_and_matching_source(tmp_path):
    licenses = tmp_path / "licenses"
    collect_licenses(licenses)
    inventory = json.loads((licenses / "inventory.json").read_text(encoding="utf-8"))
    assert {"PyQt6", "PyQt6-Qt6", "PyQt6-sip", "psutil"} <= {
        item["name"] for item in inventory["packages"]
    }
    assert (licenses / "Python-LICENSE.txt").stat().st_size > 1000
    source = tmp_path / "source.zip"
    root = Path(__file__).resolve().parents[1]
    collect_source(root, licenses, source)
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        assert "scripts/build.ps1" in names
        assert "uv.lock" in names
        assert not any(".venv" in name or "__pycache__" in name or name.endswith(".pyc") for name in names)
        assert "WiFi.bat" not in names
        assert archive.read("system_repair/audit.py") == (root / "system_repair/audit.py").read_bytes()
        gpl = archive.read("LICENSE-GPL-3.0.txt").decode("utf-8")
        assert "Version 3, 29 June 2007" in gpl
        assert "END OF TERMS AND CONDITIONS" in gpl
