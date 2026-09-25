from system_repair.model import RegistryAddress, RegistryChange, RegistryValue, Repair

POLICIES = r"Software\Microsoft\Windows\CurrentVersion\Policies"
EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
INTERNET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"


def remove_policy(key: str, name: str) -> tuple[RegistryChange, ...]:
    return tuple(RegistryChange(RegistryAddress(hive, key, name), None)
                 for hive in ("HKCU", "HKLM"))


REPAIRS = (
    Repair("taskmgr", "Политики", "Диспетчер задач", "Удалить DisableTaskMgr (HKCU / HKLM).",
           changes=remove_policy(POLICIES + r"\System", "DisableTaskMgr")),
    Repair("regedit", "Политики", "Редактор реестра", "Удалить DisableRegistryTools (HKCU / HKLM).",
           changes=remove_policy(POLICIES + r"\System", "DisableRegistryTools")),
    Repair("cmd", "Политики", "Командная строка", "Удалить DisableCMD (HKCU / HKLM).",
           changes=remove_policy(r"Software\Policies\Microsoft\Windows\System", "DisableCMD")),
    Repair("hidden", "Проводник", "Показывать скрытые файлы", "Hidden = 1 (текущий пользователь).",
           changes=(RegistryChange(RegistryAddress("HKCU", EXPLORER, "Hidden"), RegistryValue(4, 1)),)),
    Repair("system_files", "Проводник", "Показывать системные файлы",
           "ShowSuperHidden = 1. Защищённые файлы станут видимыми; не удаляйте их.",
           changes=(RegistryChange(RegistryAddress("HKCU", EXPLORER, "ShowSuperHidden"), RegistryValue(4, 1)),)),
    Repair("folder_options", "Проводник", "Параметры папок", "Удалить NoFolderOptions (HKCU / HKLM).",
           changes=remove_policy(POLICIES + r"\Explorer", "NoFolderOptions")),
    Repair("run_dialog", "Проводник", "Команда «Выполнить»", "Удалить NoRun (HKCU / HKLM).",
           changes=remove_policy(POLICIES + r"\Explorer", "NoRun")),
    Repair("uac", "Политики", "Включить UAC",
           "EnableLUA = 1 (HKLM). Только включение защиты; потребуется перезагрузка.",
           changes=(RegistryChange(RegistryAddress("HKLM", POLICIES + r"\System", "EnableLUA"), RegistryValue(4, 1)),),
           reboot=True),
    Repair("drives", "Проводник", "Показать скрытые диски",
           "Удалить NoDrives и NoViewOnDrive (HKCU / HKLM). Права NTFS не изменяются.",
           changes=remove_policy(POLICIES + r"\Explorer", "NoDrives") + remove_policy(POLICIES + r"\Explorer", "NoViewOnDrive")),
    Repair("gpedit", "Политики", "Разрешить редактор групповых политик",
           "Снять Restrict_Run оснастки gpedit. Не устанавливает gpedit в Home и не обходит доменную политику MMC.",
           changes=remove_policy(r"Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}", "Restrict_Run")),
    Repair("exe_assoc", "Ассоциации", "Восстановить .exe (HKCU)",
           "Текущий пользователь: .exe → exefile; shell\\open\\command = \"%1\" %*. UserChoice и политики не обходятся.",
           changes=(
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\.exe", ""), RegistryValue(1, "exefile")),
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\exefile\shell\open\command", ""), RegistryValue(1, '"%1" %*')),
           )),
    Repair("bat_assoc", "Ассоциации", "Восстановить .bat (HKCU)",
           "Текущий пользователь: .bat → batfile; стандартная команда открытия. Сценарии не запускаются.",
           changes=(
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\.bat", ""), RegistryValue(1, "batfile")),
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\batfile\shell\open\command", ""), RegistryValue(1, '"%1" %*')),
           )),
    Repair("lnk_assoc", "Ассоциации", "Восстановить .lnk (HKCU)",
           "Текущий пользователь: .lnk → lnkfile, маркер IsShortcut. COM-обработчики и UserChoice не переписываются.",
           changes=(
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\.lnk", ""), RegistryValue(1, "lnkfile")),
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\lnkfile", "IsShortcut"), RegistryValue(1, "")),
           )),
    Repair("reg_assoc", "Ассоциации", "Восстановить .reg (HKCU)",
           "Текущий пользователь: .reg → regfile; открытие в штатном Regedit. Файлы не импортируются.",
           changes=(
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\.reg", ""), RegistryValue(1, "regfile")),
               RegistryChange(RegistryAddress("HKCU", r"Software\Classes\regfile\shell\open\command", ""), RegistryValue(2, '"%SystemRoot%\\regedit.exe" "%1"')),
           )),
    Repair("proxy", "Сеть", "Отключить пользовательский прокси",
           "ProxyEnable = 0; удалить ProxyServer и AutoConfigURL (PAC) в HKCU. "
           "WinHTTP, WPAD и управляемые политики не изменяются.",
           changes=(
               RegistryChange(RegistryAddress("HKCU", INTERNET, "ProxyEnable"), RegistryValue(4, 0)),
               RegistryChange(RegistryAddress("HKCU", INTERNET, "ProxyServer"), None),
               RegistryChange(RegistryAddress("HKCU", INTERNET, "AutoConfigURL"), None),
           )),
    Repair("hosts", "Сеть", "Сбросить файл hosts",
           "Удалить все активные записи hosts, включая легитимные локальные адреса.", kind="hosts"),
    Repair("winsock", "Сеть", "Сбросить каталог WinSock",
           "netsh winsock reset. Возможны потеря связи и сбой VPN. "
           "Нужна точка восстановления; после операции — перезагрузка.", kind="winsock", reboot=True),
    Repair("tcpip", "Сеть", "Сбросить TCP/IP",
           "netsh int ip reset. Статические IP/DNS могут быть сброшены. "
           "Не выполнять по RDP; нужна точка восстановления и перезагрузка.", kind="tcpip", reboot=True),
)
BY_ID = {repair.id: repair for repair in REPAIRS}

NETWORK_BRANCHES = (
    r"SYSTEM\CurrentControlSet\Services\WinSock",
    r"SYSTEM\CurrentControlSet\Services\WinSock2",
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Dhcp\Parameters",
    r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
)

DEFAULT_HOSTS = (
    "# Default local hosts file.\r\n"
    "# Localhost name resolution is handled within DNS itself.\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n"
).encode("ascii")


def selected_repairs(ids: list[str] | tuple[str, ...]) -> tuple[Repair, ...]:
    if not ids:
        raise ValueError("Выберите хотя бы одно исправление.")
    if len(ids) != len(set(ids)) or any(item not in BY_ID for item in ids):
        raise ValueError("Неизвестное или повторное исправление.")
    selected = set(ids)
    return tuple(repair for repair in REPAIRS if repair.id in selected)
