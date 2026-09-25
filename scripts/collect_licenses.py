from __future__ import annotations

import json
import shutil
import sys
import sysconfig
from importlib.metadata import distribution
from pathlib import Path


def collect(destination: Path) -> None:
    names = ["PyQt6", "PyQt6-Qt6", "PyQt6-sip", "psutil", "pyinstaller",
             "pyinstaller-hooks-contrib", "altgraph", "packaging", "setuptools"]
    if sys.platform == "win32":
        names.extend(("pywin32", "pywin32-ctypes", "pefile"))
    inventory = []
    for name in names:
        package = distribution(name)
        copied = []
        for entry in package.files or ():
            if not any(word in str(entry).lower() for word in ("license", "copying", "notice")):
                continue
            source = Path(package.locate_file(entry))
            if source.is_file() and ".." not in entry.parts:
                target = destination / name / entry
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                copied.append(str(target.relative_to(destination)).replace("\\", "/"))
        if not copied:
            raise RuntimeError(f"No license found for {name}; distribution aborted.")
        inventory.append({"name": name, "version": package.version, "licenses": copied})

    candidates = (Path(sys.base_prefix) / "LICENSE.txt",
                  Path(sysconfig.get_path("stdlib")) / "LICENSE.txt")
    python_license = next((path for path in candidates if path.is_file()), None)
    if python_license is None:
        raise RuntimeError("Python license is missing; distribution aborted.")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(python_license, destination / "Python-LICENSE.txt")
    manifest = {"python": sys.version, "packages": inventory}
    (destination / "inventory.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    collect(Path(sys.argv[1]))
