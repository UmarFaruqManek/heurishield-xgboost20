param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('url17', 'url20')]
    [string]$Model,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$inputFile = Join-Path $projectRoot 'data\evaluation\legitimate_fresh_500_dual_06nov2026.txt'
if ($Model -eq 'url20') {
    & (Join-Path $PSScriptRoot 'Uji_Live_URL20.ps1') -InputFile $inputFile -Label legitimate -Parallel 1 -DryRun:$DryRun
    exit $LASTEXITCODE
}

$extensionRoot = (Join-Path $projectRoot 'comparators\HeuriShield-URL17-XGBoost')
$manifest = Get-Content -LiteralPath (Join-Path $extensionRoot 'manifest.json') -Raw | ConvertFrom-Json
$modelPath = Join-Path $extensionRoot 'src\model\xgboost-url18.json'
$configuration = Get-Content -LiteralPath $modelPath -Raw | ConvertFrom-Json
if ($configuration.feature_names.Count -ne 17 -or $configuration.threshold -ne 0.45) {
    throw 'Konfigurasi extension URL17 tidak sesuai 17 fitur TH0.45.'
}
if (-not (Test-Path -LiteralPath $inputFile)) { throw "File input tidak ditemukan: $inputFile" }
if ($DryRun) {
    [pscustomobject]@{
        extension = $extensionRoot
        version = $manifest.version
        features = $configuration.feature_names.Count
        threshold = $configuration.threshold
        input = $inputFile
    } | ConvertTo-Json
    exit 0
}

$runId = 'url17_v037_legitimate_' + (Get-Date -Format 'yyyyMMdd_HHmmss')
$reportRoot = Join-Path $projectRoot ('testing\live\' + $runId)
$historyPath = Join-Path $projectRoot 'data\evaluation\history_url17.sqlite'
python (Join-Path $PSScriptRoot 'evaluate-extension-browser-live.py') `
    --extension-dir $extensionRoot `
    --input $inputFile `
    --label legitimate `
    --out-dir $reportRoot `
    --history-db $historyPath `
    --isolated-per-url `
    --parallel 1 `
    --checkpoint-every 25
if ($LASTEXITCODE -ne 0) { throw "Pengujian gagal. Periksa $reportRoot" }
Write-Host "Hasil pengujian tersimpan di $reportRoot"
