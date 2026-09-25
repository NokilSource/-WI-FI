# Лицензии и сторонние компоненты

System Repair 0.2 использует **PyQt6 под GPLv3 или коммерческой лицензией Riverbank**.
PyQt6 — не LGPL. Не путайте лицензию привязок PyQt6 с лицензиями отдельных
библиотек Qt, используемых приложением: у модулей Qt действуют собственные условия
(включая LGPL/GPL и коммерческие условия). Для закрытого распространения PyQt6 нужна
подходящая коммерческая лицензия; для open-source распространения исполняйте
обязательства применимых GPL/LGPL-лицензий Qt.

| Компонент (зафиксирован в `uv.lock`) | Назначение | Лицензия / распространение |
| --- | --- | --- |
| Python 3.12 | Интерпретатор | Python Software Foundation License; копия включается в `licenses/` |
| PyQt6 6.11.0 | Привязки Python к Qt | GPLv3 или коммерческая лицензия Riverbank; **не LGPL** |
| PyQt6-Qt6 6.11.2 | Библиотеки Qt | Лицензия зависит от Qt-модуля/сборки (GPL/LGPL/коммерческая); соблюдайте уведомления каждой библиотеки |
| PyQt6-sip 13.12.0 | SIP-модуль для привязок Qt | BSD-2-Clause; копия включается в `licenses/` |
| psutil 7.2.2 | Информация о процессах | BSD-3-Clause |
| pywin32 312 | Windows COM/SCM и связанные API | Только Windows; у компонентов есть собственные файлы лицензий/уведомлений в `licenses/`; проверяйте применимые условия |
| PyInstaller 6.22.3 | Упаковка приложения | GPL с исключением для распространяемых приложений |

Исполняемый код самого System Repair, его тесты, скрипты сборки и документация
распространяются под **GPL-3.0-only** согласно `LICENSE-SYSTEM-REPAIR`. Эта лицензия
не заменяет лицензии сторонних библиотек и **не распространяется на отдельный
`WiFi.bat`**. Скрипт остаётся в корне исходного репозитория, не включается в бинарные
пакеты и `SystemRepair-source.zip` и не изменяется этой сборкой.

## Содержимое сборки и исходный код

`scripts/collect_licenses.py` собирает полные доступные файлы лицензий и уведомлений
установленных runtime/build-пакетов и пишет `inventory.json` с версиями. Лицензия
Python копируется как `Python-LICENSE.txt`: сначала из `sys.base_prefix/LICENSE.txt`,
а если этого файла там нет — из `sysconfig.get_path("stdlib")/LICENSE.txt`.
Если лицензия Python не найдена, сбор её текстов прекращается с ошибкой.
В Windows-сборку входят лицензии PyQt6, Qt, SIP, psutil, pywin32 и PyInstaller,
а также лицензии нужных транзитивных пакетов и hooks PyInstaller. Лицензии упакованы
в `licenses/` архива; лицензии приложения также входят в ресурсы EXE.

Перед каждой сборкой `scripts/collect_source.py` формирует `SystemRepair-source.zip`
из Python-модулей, скриптов и тестов текущего рабочего дерева, а также
`README.md`, `THIRD_PARTY.md`, `pyproject.toml`, `uv.lock`, манифеста и workflow.
Полный текст GPLv3 берётся из файла `LICENSE` дистрибутива PyQt6 в `licenses/`;
скрипт проверяет его целостность и добавляет в архив как `LICENSE-GPL-3.0.txt`.
Поэтому вместе с бинарником получатель получает лицензию и
соответствующий исходный код именно собираемой версии. При распространении своих
изменённых сборок пересоберите архив исходников для той же ревизии и выполните все
обязательства GPL/LGPL и лицензий включённых библиотек.

Доступны две упаковки PyInstaller: onefile (исполняемый файл распаковывает необходимые
компоненты во временную папку при запуске) и onedir (библиотеки находятся рядом в
дереве приложения). Это упаковка Python/Qt, **не статическая компиляция**. В обоих
случаях ZIP содержит лицензионные файлы и `SystemRepair-source.zip`. Имена архивов:
`dist/SystemRepair-windows-x64-onefile.zip` и
`dist/SystemRepair-windows-x64-onedir.zip`.

Автоматическая сборка Windows в GitHub Actions настроена на оба режима и smoke-тест
демонстрационного запуска на реальной Windows-среде runner. Сборочный скрипт
платформенно ограничен Windows x64; Linux runner выполняет проверки, но не производит
нативный Linux PyInstaller-дистрибутив и не заменяет Windows-сборку. Этот файл описывает
правила сборки, а не подтверждает успех конкретного CI-запуска или наличие
опубликованного бинарника. `tests/test_packaging.py` также требует установленных
зависимостей группы `build`, поэтому для тестового набора используйте
`uv sync --frozen --group dev --group build`.

## Ссылки на лицензии

- [PyQt6 licensing](https://riverbankcomputing.com/static/Docs/PyQt6/introduction.html#license)
- [Qt open-source obligations](https://www.qt.io/licensing/open-source-lgpl-obligations)
- [PyInstaller license](https://pyinstaller.org/en/stable/license.html)
- [Python license](https://docs.python.org/3/license.html)
- [PyQt6-sip 13.12.0 on PyPI](https://pypi.org/project/PyQt6-sip/13.12.0/)
- [psutil BSD-3-Clause](https://github.com/giampaolo/psutil/blob/master/LICENSE)
- [pywin32 upstream source and license notices](https://github.com/mhammond/pywin32)

Версии и платформенные маркеры зависимостей зафиксированы в `pyproject.toml` и
`uv.lock`; фактический состав конкретного архива перечислен в его `licenses/inventory.json`.
