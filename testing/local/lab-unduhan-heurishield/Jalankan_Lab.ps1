$ErrorActionPreference = 'Stop'
python (Join-Path $PSScriptRoot 'lab.py')
if ($LASTEXITCODE -ne 0) { throw 'Laboratorium berhenti dengan error. Periksa pesan di terminal.' }
