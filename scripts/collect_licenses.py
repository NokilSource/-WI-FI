import shutil
import sys
from importlib.metadata import distribution
from pathlib import Path

destination = Path(sys.argv[1])
for name in ("PySide6", "PySide6_Essentials", "PySide6_Addons", "shiboken6", "psutil", "pyinstaller"):
    package = distribution(name)
    for entry in package.files or ():
        if not any(word in str(entry).lower() for word in ("license", "copying", "notice")):
            continue
        source = Path(package.locate_file(entry))
        if source.is_file() and ".." not in entry.parts:
            target = destination / name / entry
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
python_license = Path(sys.base_prefix) / "LICENSE.txt"
if python_license.is_file():
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(python_license, destination / "Python-LICENSE.txt")
