param([ValidateSet('onefile', 'onedir')][string]$Mode = 'onefile')
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Build on 64-bit Windows using 64-bit Python 3.12.'
}
uv sync --frozen --group build
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
if (Test-Path build/licenses) { Remove-Item -LiteralPath build/licenses -Recurse -Force }
uv run --frozen python scripts/collect_licenses.py build/licenses
if ($LASTEXITCODE -ne 0) { throw 'License collection failed.' }
uv run --frozen python scripts/collect_source.py build/licenses build/SystemRepair-source.zip
if ($LASTEXITCODE -ne 0) { throw 'Corresponding source collection failed.' }
$manifest = (Resolve-Path packaging/app.manifest).Path
$licenses = (Resolve-Path build/licenses).Path
$appLicense = (Resolve-Path LICENSE-SYSTEM-REPAIR).Path
$app = (Resolve-Path scripts/app.py).Path
uv run --frozen pyinstaller --noconfirm --clean "--$Mode" --windowed --name SystemRepair --specpath build --manifest $manifest --hidden-import win32timezone --add-data "$licenses;licenses" --add-data "$appLicense;." $app
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
$exe = if ($Mode -eq 'onefile') { 'dist/SystemRepair.exe' } else { 'dist/SystemRepair/SystemRepair.exe' }
$process = Start-Process -FilePath (Resolve-Path $exe) -ArgumentList '--demo', '--smoke-test' -PassThru
if (-not $process.WaitForExit(60000)) {
    $process.Kill()
    throw 'Packaged demo did not complete the smoke test in 60 seconds.'
}
if ($process.ExitCode -ne 0) { throw "Packaged demo failed: $($process.ExitCode)" }
$bundle = "dist/SystemRepair-$Mode-package"
if (Test-Path $bundle) { Remove-Item -LiteralPath $bundle -Recurse -Force }
New-Item -ItemType Directory -Force -Path $bundle | Out-Null
if ($Mode -eq 'onefile') { Copy-Item $exe $bundle } else { Copy-Item dist/SystemRepair $bundle -Recurse -Force }
Copy-Item README.md,THIRD_PARTY.md,LICENSE-SYSTEM-REPAIR $bundle
Copy-Item build/licenses $bundle -Recurse -Force
Copy-Item build/SystemRepair-source.zip $bundle
$archive = "dist/SystemRepair-windows-x64-$Mode.zip"
Compress-Archive -Path "$bundle/*" -DestinationPath $archive -Force
Get-FileHash $archive -Algorithm SHA256
