from __future__ import annotations

import ntpath

from system_repair.catalog import IFEO, WINLOGON
from system_repair.model import Finding, Platform


def inspect_startup(platform: Platform) -> list[Finding]:
    findings = []
    windows = platform.identity()["windows"]
    for hive in ("HKCU", "HKLM"):
        for view in (64, 32):
            for suffix in ("Run", "RunOnce"):
                key = rf"Software\Microsoft\Windows\CurrentVersion\{suffix}"
                location = f"{hive}\\{key} [{view}]"
                try:
                    findings.extend(Finding(suffix, name, location, value.display())
                                    for name, value in platform.registry_values(hive, key, view).items())
                except OSError as error:
                    findings.append(Finding(suffix, "Ошибка чтения", location, str(error), "Ошибка"))
            location = f"{hive}\\{WINLOGON} [{view}]"
            try:
                values = platform.registry_values(hive, WINLOGON, view)
                for name, value in values.items():
                    if name.casefold() not in ("userinit", "shell"):
                        continue
                    text = value.display().strip().casefold()
                    text = text.replace("%systemroot%", windows.casefold()).replace("%windir%", windows.casefold())
                    expected = ({"explorer.exe", ntpath.join(windows, "explorer.exe").casefold()}
                                if name.casefold() == "shell" else
                                {ntpath.join(windows, "system32", "userinit.exe").casefold() + ","})
                    status = "Типовое" if hive == "HKLM" and value.type in (1, 2) and text in expected else "Проверить"
                    findings.append(Finding("Winlogon", name, location, value.display(), status))
            except OSError as error:
                findings.append(Finding("Winlogon", "Ошибка чтения", location, str(error), "Ошибка"))

    for view in (64, 32):
        for executable in ("cmd.exe", "regedit.exe", "taskmgr.exe"):
            pending = [(IFEO + "\\" + executable, 0)]
            visited = 0
            while pending:
                key, depth = pending.pop()
                location = f"HKLM\\{key} [{view}]"
                try:
                    visited += 1
                    if depth > 8 or visited > 256:
                        raise OSError("Слишком много вложенных IFEO-фильтров; проверьте ветку вручную.")
                    findings.extend(Finding("IFEO", name, location, value.display())
                                    for name, value in platform.registry_values("HKLM", key, view).items())
                    pending.extend((key + "\\" + name, depth + 1)
                                   for name in platform.registry_subkeys("HKLM", key, view))
                except OSError as error:
                    findings.append(Finding("IFEO", executable, location, str(error), "Ошибка"))
                    break
    return findings
