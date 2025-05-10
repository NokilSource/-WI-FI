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

for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| findstr /i /C:"Все профили пользователя" /C:"All User Profile"') do (
    set "profile=%%a"
    setlocal enabledelayedexpansion
    set "profile=!profile:~1!"
    set "profile=!profile:"=!"
    
    echo ----------------------------------------------
    echo Сеть Wi-Fi:  !profile!
    echo ----------------------------------------------
    
    for /f "tokens=1,* delims=:" %%k in ('netsh wlan show profile name^="!profile!" key^=clear ^| findstr /i /C:"Security key" /C:"Содержимое ключа" /C:"Key Content"') do (
        set "key_line=%%k"
        set "value=%%l"
        setlocal enabledelayedexpansion
        set "key_line=!key_line:Содержимое ключа=Пароль!"
        set "key_line=!key_line:Key Content=Password!"
        if not "!value!"=="" (
            echo !key_line!: !value:~1!
        ) else (
            echo Пароль: [не найден или отсутствует]
        )
        endlocal
    )
    echo.
    endlocal
)

echo.
echo.
echo Подписывайтесь на канал Nokil:
echo → https://youtube.com/@nokiloriginall
echo → https://github.com/NokilSource
echo.

pause
