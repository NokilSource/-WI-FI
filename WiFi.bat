:: Программа для отоброжения пароля от WiFi
:: https://youtube.com/@nokiloriginall
:: https://github.com/NokilSource
:: _   _       _    _ _ _ 
::| \ | | ___ | | _(_) | |
::|  \| |/ _ \| |/ / | | |
::| |\  | (_) |   <| | | |
::|_| \_|\___/|_|\_\_|_|_|
::  
@echo off
chcp 65001 > nul

echo ==================================================
echo              Поиск паролей Wi-Fi
echo ==================================================
echo.

set "profiles_found="
for /f "tokens=1,* delims=:" %%a in ('netsh wlan show profiles ^| findstr /i /C:"Все профили пользователя" /C:"All User Profile"') do (
    set "profiles_found=1"
    set "profile=%%b"
    setlocal enabledelayedexpansion
    set "profile=!profile:~1!"
    set "profile=!profile:"=!"
    
    echo ----------------------------------------------
    echo Сеть Wi-Fi:  !profile!
    echo ----------------------------------------------
    
    set "password_found="
    for /f "tokens=1,* delims=:" %%k in ('netsh wlan show profile name^="!profile!" key^=clear ^| findstr /i /C:"Содержимое ключа" /C:"Key Content"') do (
        set "value=%%l"
        if defined value (
            set "password_found=1"
            echo Пароль: !value:~1!
        )
    )
    if not defined password_found echo Пароль: [не сохранён или недоступен]
    echo.
    endlocal
)
if not defined profiles_found echo Сохранённые сети Wi-Fi не найдены или служба WLAN недоступна.

echo.
echo.
echo Подписывайтесь на канал Nokil:
echo → https://youtube.com/@nokiloriginall
echo → https://github.com/NokilSource
echo.

pause
