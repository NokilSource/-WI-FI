from __future__ import annotations

import sys
import zipfile
from pathlib import Path


def collect(root: Path, licenses: Path, destination: Path) -> None:
    gpl = next((licenses / "PyQt6").rglob("LICENSE"))
    text = gpl.read_text(encoding="utf-8")
    if "GNU GENERAL PUBLIC LICENSE" not in text or "END OF TERMS AND CONDITIONS" not in text:
        raise RuntimeError("The complete GPLv3 license must accompany the source.")
    sources = [root / name for name in (
        "README.md", "THIRD_PARTY.md", "LICENSE-SYSTEM-REPAIR", "pyproject.toml",
        "uv.lock", ".python-version", "packaging/app.manifest", ".github/workflows/windows-build.yml",
    )]
    for folder in ("system_repair", "scripts", "tests"):
        sources.extend(path for path in (root / folder).rglob("*")
                       if path.is_file() and path.suffix in (".py", ".sh", ".ps1"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(sources):
            archive.write(path, str(path.relative_to(root)))
        archive.write(gpl, "LICENSE-GPL-3.0.txt")


if __name__ == "__main__":
    collect(Path(__file__).resolve().parents[1], Path(sys.argv[1]), Path(sys.argv[2]))
