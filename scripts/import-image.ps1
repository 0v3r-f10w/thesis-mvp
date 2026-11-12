# import-image.ps1
# Build the dsh-toolbox image and import it into every kind node.
#
# The A/B experiment has two arms:
#   baseline : alpine:latest      (busybox: sh + wget)
#   toolbox  : dsh-toolbox:22.04  (ubuntu: curl/jq/gcc/openssl)  <- this script
#
# Single-variable rule:
#   The toolbox image MUST NOT contain kubectl. Kubernetes interaction in both
#   arms goes through the raw HTTPS API only, so any measured difference is
#   attributable to tool quality and not to having a K8s client.
#   The Dockerfile asserts kubectl absence at build time and fails if present.
#
# Usage:
#   .\scripts\import-image.ps1
#   .\scripts\import-image.ps1 -SkipBuild
#
# Compatible with Windows PowerShell 5.1 and PowerShell 7 or later.
# Contains only ASCII characters. Does not use the ampersand-ampersand operator.

param(
    [string]$Tag = "dsh-toolbox:22.04",
    [string[]]$Nodes = @("desktop-control-plane", "desktop-worker"),
    [switch]$SkipBuild
)

# Stop on the first error instead of continuing.
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

# Pipe raw file bytes into a native command's stdin.
# Windows PowerShell 5.1 uses -Encoding Byte; PowerShell 6 and later use
# -AsByteStream. Parameter sets differ, so a runtime split is unavoidable.
function Send-FileBytesToStdin {
    param(
        [string]$Path,
        [string[]]$ExecArgs
    )
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Get-Content $Path -AsByteStream -ReadCount 0 | docker @ExecArgs
    } else {
        Get-Content $Path -Encoding Byte -ReadCount 0 | docker @ExecArgs
    }
}

function Assert-Docker {
    $ver = ""
    try {
        $ver = docker version --format '{{.Server.Version}}' 2>&1
    } catch {
        $ver = "docker CLI not available: $_"
    }
    if ($LASTEXITCODE -ne 0) {
        throw ("docker is not reachable. Start Docker Desktop and run this script " +
               "in a terminal that has docker permission. Detail: " + $ver)
    }
    Write-Host ("docker OK (server " + $ver + ")")
}

function Assert-Kubectl {
    $cmd = Get-Command kubectl -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        throw "kubectl not found in PATH"
    }
    $ctx = kubectl config current-context 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("kubectl cannot read the current context. Detail: " + $ctx)
    }
    Write-Host ("kubectl context: " + $ctx)
}

function Import-ImageIntoNode {
    param(
        [string]$NodeName,
        [string]$TarPath
    )

    $running = @(docker ps --format "{{.Names}}")
    if ($LASTEXITCODE -ne 0) {
        throw ("docker ps failed while checking node " + $NodeName)
    }
    if (-not ($running -contains $NodeName)) {
        Write-Warning ("node container " + $NodeName + " is not running; skipping")
        return $false
    }

    Write-Host ("importing " + $TarPath + " into node " + $NodeName + " ...")
    Send-FileBytesToStdin -Path $TarPath -ExecArgs @(
        "exec", "-i", $NodeName, "ctr", "-n", "k8s.io", "images", "import", "-"
    )
    if ($LASTEXITCODE -ne 0) {
        throw ("ctr import failed on node " + $NodeName)
    }
    Write-Host ("node " + $NodeName + " OK") -ForegroundColor Green
    return $true
}

# Resolve repo root. This script lives in <root>/scripts.
$root = Split-Path -Parent $PSScriptRoot
$imageDir = Join-Path $root "images"
$dockerfile = Join-Path $imageDir "Dockerfile.toolbox"
$safeName = $Tag -replace "[:/]", "-"
$tarPath = Join-Path $env:TEMP ("dsh-toolbox-" + $safeName + ".tar")

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
Write-Step "0. Preflight"
Assert-Docker
Assert-Kubectl

if (-not (Test-Path $dockerfile)) {
    throw ("Dockerfile not found: " + $dockerfile)
}
Write-Host ("Dockerfile: " + $dockerfile)

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------
if ($SkipBuild) {
    Write-Step "1. Build skipped (-SkipBuild)"
    $haveImage = docker images -q $Tag 2>&1
    if (-not $haveImage) {
        throw ("image " + $Tag + " does not exist locally and -SkipBuild was specified")
    }
} else {
    Write-Step ("1. docker build -t " + $Tag)
    docker build -f $dockerfile -t $Tag $imageDir
    if ($LASTEXITCODE -ne 0) {
        throw "docker build failed"
    }
}

# ---------------------------------------------------------------------------
# 2. Verify toolchain and kubectl absence
#    The Dockerfile already asserts this at build time. This is an independent
#    check on the resulting image, run as a separate container.
# ---------------------------------------------------------------------------
Write-Step "2. Verify toolchain and kubectl absence"

$checkCommand = "set -e; " +
    "for t in curl wget gcc make jq nc dig ps openssl bash file; do " +
    "command -v `"`$t`" >/dev/null 2>&1 || { echo MISSING `"`$t`"; exit 1; }; " +
    "echo OK `"`$t`"; done; " +
    "if command -v kubectl >/dev/null 2>&1; then " +
    "echo FATAL-kubectl-present; exit 1; " +
    "else echo OK-kubectl-absent; fi"

docker run --rm --entrypoint bash $Tag -c $checkCommand
if ($LASTEXITCODE -ne 0) {
    throw "image verification failed: a tool is missing or kubectl leaked into the image"
}
Write-Host "image verification passed" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. docker save
# ---------------------------------------------------------------------------
Write-Step ("3. docker save -o " + $tarPath)
docker save -o $tarPath $Tag
if ($LASTEXITCODE -ne 0) {
    throw ("docker save failed for " + $Tag)
}
$sizeMb = [math]::Round((Get-Item $tarPath).Length / 1MB, 1)
Write-Host ("tar: " + $tarPath + " (" + $sizeMb + " MB)")

# ---------------------------------------------------------------------------
# 4. Import into each node
# ---------------------------------------------------------------------------
$imported = @()
foreach ($node in $Nodes) {
    Write-Step ("4. Import into node " + $node)
    $ok = Import-ImageIntoNode -NodeName $node -TarPath $tarPath
    if ($ok) {
        $imported += $node
    }
}
if ($imported.Count -eq 0) {
    throw "no node received the image; check node container names with: docker ps"
}

# ---------------------------------------------------------------------------
# 5. Verify on the cluster side
# ---------------------------------------------------------------------------
Write-Step "5. Verification"
$verified = 0
foreach ($node in $imported) {
    $out = docker exec $node ctr -n k8s.io images ls -q 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("cannot list images on " + $node)
        continue
    }
    $match = $out | Select-String -SimpleMatch $Tag
    if ($match) {
        Write-Host ("  [" + $node + "] " + ($match | Select-Object -First 1)) -ForegroundColor Green
        $verified = $verified + 1
    } else {
        Write-Warning ("  [" + $node + "] " + $Tag + " not found after import")
    }
}
if ($verified -eq 0) {
    throw ("verification failed: " + $Tag + " not visible on any node")
}

# ---------------------------------------------------------------------------
# 6. Done
# ---------------------------------------------------------------------------
Write-Step "Done"
Write-Host ("toolbox image is ready on: " + ($imported -join ", ")) -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host ("  1) dry run (setup and healthcheck only, no tokens spent)" ) -ForegroundColor Yellow
Write-Host ("       python -m app.run --scenario k8s_rbac_permissions --image " + $Tag + " --dry-run") -ForegroundColor Yellow
Write-Host ""
Write-Host "  2) mock smoke test (verifies bash shell adaptation)" -ForegroundColor Yellow
Write-Host ("       python -m app.run --scenario k8s_rbac_permissions --image " + $Tag + " --llm mock --mode multi") -ForegroundColor Yellow
Write-Host ""
Write-Host "  3) real A/B experiment" -ForegroundColor Yellow
Write-Host "       python outputs/logs/run_image_ablation.py --reps 3" -ForegroundColor Yellow
Write-Host ""
Write-Host ("The tar file is kept at: " + $tarPath) -ForegroundColor Yellow
Write-Host "Delete it manually if you no longer need it." -ForegroundColor Yellow
