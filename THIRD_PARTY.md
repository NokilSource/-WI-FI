# Сторонние компоненты

Приложение использует Python (PSF License), PySide6 / Qt / Shiboken (LGPLv3,
GPL или коммерческая лицензия Qt, в зависимости от компонента) и psutil
(BSD-3-Clause). Для сборки используется PyInstaller (GPL с исключением
для распространяемых приложений).

Сборка — **onedir**: библиотеки Qt находятся отдельно от приложения и могут
быть заменены совместимыми сборками. Не распространяйте один `SystemRepair.exe`
без соседней папки `_internal`. Скрипт сборки копирует доступные тексты лицензий
и уведомления из установленных пакетов в `licenses/`.

- Qt for Python: https://doc.qt.io/qtforpython-6/licenses.html
- Qt licensing: https://www.qt.io/licensing/open-source-lgpl-obligations
- psutil: https://github.com/giampaolo/psutil/blob/master/LICENSE
- PyInstaller: https://pyinstaller.org/en/stable/license.html

Перед распространением модифицированной сборки проверьте обязанности по
лицензиям её компонентов. Версии и хеши Python-пакетов находятся в `uv.lock`.
