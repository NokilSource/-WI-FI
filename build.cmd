@echo off
rem ============================================================
rem  AegisKit — сценарий сборки
rem  Использование:
rem    build.cmd            — обычная сборка Release (нужен .NET Desktop Runtime 8)
rem    build.cmd single     — единый самодостаточный exe (~70 МБ) -> publish\AegisKit.exe
rem                           Работает и в среде восстановления (WinRE/WinPE) без .NET.
rem    build.cmd selftest   — сборка без требования UAC + рендер всех страниц в PNG
rem ============================================================
setlocal
cd /d "%~dp0"

set DOTNET=dotnet
if exist "..\.dotnet\dotnet.exe" set DOTNET=..\.dotnet\dotnet.exe

"%DOTNET%" --version >nul 2>nul
if errorlevel 1 (
    echo [.NET 8 SDK не найден. Установите: https://dotnet.microsoft.com/download/dotnet/8.0]
    exit /b 1
)

if "%1"=="single" goto single
if "%1"=="selftest" goto selftest

:default
echo [1/2] Сборка AegisKit (Release)...
"%DOTNET%" build AegisKit.sln -c Release -v q || exit /b 1
echo [2/2] Готово: src\AegisKit.App\bin\x64\Release\net8.0-windows\AegisKit.exe
goto :eof

:single
echo [1/2] Публикация единого exe (self-contained win-x64, один файл)...
"%DOTNET%" publish src\AegisKit.App -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:IncludeAllContentForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -v q -o publish || exit /b 1
echo [2/2] Готово: publish\AegisKit.exe — один файл, распространяется как есть.
goto :eof

:selftest
rem Приложение требует прав администратора, поэтому для автоматической проверки
rem собираем вариант с манифестом asInvoker и запускаем без запроса UAC.
echo [1/2] Сборка варианта без UAC...
"%DOTNET%" build src\AegisKit.App\AegisKit.App.csproj -c Release ^
  -p:TestManifest=true -p:BaseOutputPath=bin_test\ -v q || exit /b 1
set AEGIS_EXE=src\AegisKit.App\bin_test\x64\Release\net8.0-windows\AegisKit.exe
if not exist "%AEGIS_EXE%" (echo [AegisKit.exe не найден] & exit /b 2)
echo [2/2] Рендер страниц...
"%AEGIS_EXE%" --selftest --out:_selftest
if errorlevel 1 (echo [selftest FAILED — см. %%TEMP%%\aegiskit_selftest.log] & exit /b 2)
echo [selftest OK] PNG: _selftest\page_*.png, вёрстка: _selftest\layout_*.txt
goto :eof
