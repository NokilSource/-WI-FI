$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Build on 64-bit Windows using 64-bit Python 3.12.'
}
uv sync --frozen --group build
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
uv run --frozen pyinstaller --noconfirm --clean --onedir --windowed --name SystemRepair --manifest packaging/app.manifest scripts/app.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
Copy-Item README.md dist/SystemRepair/README.md
Copy-Item THIRD_PARTY.md dist/SystemRepair/THIRD_PARTY.md
uv run --frozen python scripts/collect_licenses.py dist/SystemRepair/licenses
if ($LASTEXITCODE -ne 0) { throw 'License collection failed.' }
$process = Start-Process -FilePath (Resolve-Path dist/SystemRepair/SystemRepair.exe) -ArgumentList '--demo', '--smoke-test' -PassThru
if (-not $process.WaitForExit(30000)) {
    $process.Kill()
    throw 'Packaged demo did not complete the smoke test in 30 seconds.'
}
if ($process.ExitCode -ne 0) { throw "Packaged demo failed: $($process.ExitCode)" }
Compress-Archive -Path dist/SystemRepair -DestinationPath dist/SystemRepair-windows-x64.zip -Force
Get-FileHash dist/SystemRepair-windows-x64.zip -Algorithm SHA256
