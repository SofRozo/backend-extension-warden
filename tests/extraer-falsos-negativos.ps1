# extraer-falsos-negativos.ps1
#
# Copia los .crx de las 13 extensiones clasificadas como BENIGNAS
# (falsos negativos del backend) a una carpeta aparte.
#
# Uso:
#   .\extraer-falsos-negativos.ps1
#   .\extraer-falsos-negativos.ps1 -SourceDir 'C:\ruta\al\dataset'
#   .\extraer-falsos-negativos.ps1 -SourceDir '...' -OutputDir 'C:\salida'

param(
    [string]$SourceDir = '',
    [string]$OutputDir = (Join-Path $PSScriptRoot 'clasificadas-incorrectamente\crx')
)

# ── Las 13 falsas negativas ─────────────────────────────────────────────────
$ids = @(
    'eggegjdejilddmnlglakcaigefefcdaf',  # InteractiveFics
    'eheagnmidghfknkcaehacggccfiidhik',  # Email checker
    'giaooddllfkkkblpaedgkhfmhocponbo',  # DeepSeek v3
    'glckmpfajbjppappjlnhhlofhdhlcgaj',  # Good Tab
    'goiffchdhlcehhgdpdbocefkohlhmlom',  # Stock Reminder
    'goikoilmhcgfidolicnbgggdpckdcoam',  # Amazon Character Count
    'hafhkoalnlpoifpidohfjlmeemfifndi',  # Grok AI
    'hkhmodcdjhcidbcncgmnknjppphcpgmh',  # Amazon Sticky Notes
    'hodafefeincjlgijbiabbmaffambjeaa',  # Grok Sidebar
    'hpkfkbmcphnigepfjmapkdaedglohgjg',  # Flappy Birdie
    'iclckldkfemlnecocpphinnplnmijkol',  # SQLite browser
    'ihdnbohcfnegemgomjcpckmpnkdgopon',  # AI Sentence Rewriter
    'johobikccpnmifjjpephegmfpipfbfme'   # Amazon Stock Checker
)

# ── Autodetectar carpeta del dataset si no se paso por parametro ────────────
if (-not $SourceDir) {
    $candidates = @(
        'c:\Users\sofro\OneDrive\Desktop\Malicious Browser Extensions',
        'c:\Users\sofro\OneDrive\Desktop\tesis\Malicious Browser Extensions',
        'c:\Users\sofro\OneDrive\Desktop\backend-tesis\Malicious Browser Extensions',
        'c:\Users\sofro\Desktop\Malicious Browser Extensions',
        'c:\Users\sofro\Documents\Malicious Browser Extensions'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $SourceDir = $c; break }
    }
}

if (-not $SourceDir -or -not (Test-Path $SourceDir)) {
    Write-Host ""
    Write-Host "ERROR: No se encontro la carpeta del dataset." -ForegroundColor Red
    Write-Host "       Pasala con: -SourceDir 'C:\ruta\al\dataset'"
    exit 1
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host ""
Write-Host "Dataset: $SourceDir"
Write-Host "Salida:  $OutputDir"
Write-Host ""

$ok = 0; $miss = 0
foreach ($id in $ids) {
    $src = Join-Path $SourceDir ($id + '.crx')
    if (Test-Path $src) {
        Copy-Item $src $OutputDir -Force
        Write-Host "  OK   $id.crx" -ForegroundColor Green
        $ok++
    } else {
        Write-Host "  SKIP $id.crx (no existe)" -ForegroundColor Yellow
        $miss++
    }
}

Write-Host ""
Write-Host "Copiados: $ok  |  No encontrados: $miss"
Write-Host "Carpeta:  $OutputDir"
