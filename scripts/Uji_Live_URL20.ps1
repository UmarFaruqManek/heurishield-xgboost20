param(
    [string]$InputFile = '',
    [ValidateSet('legitimate', 'phishing')]
    [string]$Label = 'phishing',
    [ValidateRange(1, 2)]
    [int]$Parallel = 1,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$extensionRoot = Join-Path $projectRoot 'extension\HeuriShield-URL20-XGBoost'
$manifest = Get-Content -LiteralPath (Join-Path $extensionRoot 'manifest.json') -Raw | ConvertFrom-Json
$modelPath = Join-Path $extensionRoot 'src\model\xgboost-url20.json'
$model = Get-Content -LiteralPath $modelPath -Raw | ConvertFrom-Json
if ($manifest.version -ne '0.5.2' -or $model.feature_names.Count -ne 20 -or $model.threshold -ne 0.5) {
    throw 'Konfigurasi extension tidak sesuai paket URL20 v0.5.2 TH0.50.'
}

$readyReport = Join-Path $projectRoot 'experiments\v2\reports\extension_ready.json'
if (-not (Test-Path -LiteralPath $readyReport)) {
    throw 'Laporan pemeriksaan akhir extension belum tersedia.'
}
$verified = Get-Content -LiteralPath $readyReport -Raw | ConvertFrom-Json
foreach ($entry in $verified.file_hashes.PSObject.Properties) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $extensionRoot $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.Value) { throw "Berkas berubah setelah verifikasi: $($entry.Name)" }
}
if ($DryRun) {
    [pscustomobject]@{
        extension = $extensionRoot
        version = $manifest.version
        features = $model.feature_names.Count
        threshold = $model.threshold
        ready = $verified.ready
        input = $InputFile
        label = $Label
        parallel = $Parallel
    } | ConvertTo-Json
    exit 0
}
if (-not $InputFile -or -not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
    throw 'Isi -InputFile dengan lokasi file URL yang akan diuji.'
}

$runId = 'url20_v052_' + $Label + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss')
$reportRoot = Join-Path $projectRoot ('testing\live\' + $runId)
$historyPath = Join-Path $projectRoot 'data\evaluation\history_url20.sqlite'
python (Join-Path $PSScriptRoot 'evaluate-extension-browser-live.py') `
    --extension-dir $extensionRoot `
    --input $InputFile `
    --label $Label `
    --out-dir $reportRoot `
    --history-db $historyPath `
    --isolated-per-url `
    --parallel $Parallel `
    --checkpoint-every 25
if ($LASTEXITCODE -ne 0) { throw "Pengujian gagal. Periksa $reportRoot" }
Write-Host "Hasil pengujian tersimpan di $reportRoot"
