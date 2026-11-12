# import-baseline.ps1
# Import the alpine:latest baseline image into every kind node.
#
# The A/B experiment has two arms:
#   baseline : alpine:latest      (busybox: sh + wget)
#   toolbox  : dsh-toolbox:22.04  (ubuntu: curl/jq/gcc/openssl)
# This script handles the baseline arm.
#
# Why per-node import is required:
#   kind stores container images in each node's local containerd. An image
#   imported only into the control-plane is invisible to a pod scheduled onto
#   the worker, and that pod fails with ErrImageNeverPull.
#
# Usage:
#   .\scripts\import-baseline.ps1
#   .\scripts\import-baseline.ps1 -FromTar C:\path\alpine.tar
#
# Compatible with Windows PowerShell 5.1 and PowerShell 7 or later.
# Contains only ASCII characters. Does not use the ampersand-ampersand operator.

param(
    [string]$Tag = "alpine:latest",
    [string[]]$Nodes = @("desktop-control-plane", "desktop-worker"),
    [string]$FromTar = ""
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

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
Write-Step "0. Preflight"
Assert-Docker
Assert-Kubectl

# ---------------------------------------------------------------------------
# 1. Make sure the image exists locally in docker
# ---------------------------------------------------------------------------
$tarPath = $FromTar

if (($tarPath -ne "") -and (Test-Path $tarPath)) {
    Write-Step ("1. Loading image from tar: " + $tarPath)
    docker load -i $tarPath
    if ($LASTEXITCODE -ne 0) {
        throw ("docker load failed for " + $tarPath)
    }
} else {
    Write-Step ("1. Checking local docker for " + $Tag)
    $existing = docker images -q $Tag 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("docker images failed. Detail: " + $existing)
    }

    if (-not $existing) {
        Write-Host "local image not found, attempting docker pull ..." -ForegroundColor Yellow
        docker pull $Tag
        if ($LASTEXITCODE -ne 0) {
            $msg = "Cannot obtain " + $Tag + ". This cluster is offline. Choose one of:`n" +
                   "  (a) On a machine WITH internet:`n" +
                   "        docker pull " + $Tag + "`n" +
                   "        docker save -o alpine.tar " + $Tag + "`n" +
                   "      Copy alpine.tar over, then run:`n" +
                   "        .\scripts\import-baseline.ps1 -FromTar .\alpine.tar`n" +
                   "  (b) If you already have an alpine image under another tag:`n" +
                   "        docker tag <existing-image> " + $Tag + "`n" +
                   "        .\scripts\import-baseline.ps1"
            throw $msg
        }
    }
    Write-Host ("local image present: " + $Tag)

    $tarPath = Join-Path $env:TEMP "alpine-latest.tar"
    if (Test-Path $tarPath) {
        Write-Step ("2. Reusing existing tar: " + $tarPath)
    } else {
        Write-Step ("2. docker save " + $Tag)
        docker save -o $tarPath $Tag
        if ($LASTEXITCODE -ne 0) {
            throw ("docker save failed for " + $Tag)
        }
    }
}

if (-not (Test-Path $tarPath)) {
    throw ("image tar not found: " + $tarPath)
}
$sizeMb = [math]::Round((Get-Item $tarPath).Length / 1MB, 1)
Write-Host ("tar: " + $tarPath + " (" + $sizeMb + " MB)")

# ---------------------------------------------------------------------------
# 3. Import into each node
# ---------------------------------------------------------------------------
$imported = @()
foreach ($node in $Nodes) {
    Write-Step ("3. Import into node " + $node)
    $ok = Import-ImageIntoNode -NodeName $node -TarPath $tarPath
    if ($ok) {
        $imported += $node
    }
}
if ($imported.Count -eq 0) {
    throw "no node received the image; check node container names with: docker ps"
}

# ---------------------------------------------------------------------------
# 4. Verify on the cluster side
# ---------------------------------------------------------------------------
Write-Step "4. Verification"
$verified = 0
foreach ($node in $imported) {
    $out = docker exec $node ctr -n k8s.io images ls -q 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("cannot list images on " + $node)
        continue
    }
    $match = $out | Select-String -SimpleMatch "alpine"
    if ($match) {
        Write-Host ("  [" + $node + "] " + ($match | Select-Object -First 1)) -ForegroundColor Green
        $verified = $verified + 1
    } else {
        Write-Warning ("  [" + $node + "] alpine not found after import")
    }
}
if ($verified -eq 0) {
    throw "verification failed: alpine not visible on any node"
}

# ---------------------------------------------------------------------------
# 5. Done
# ---------------------------------------------------------------------------
Write-Step "Done"
Write-Host ("baseline image is ready on: " + ($imported -join ", ")) -ForegroundColor Yellow
Write-Host ""
Write-Host "Next step:" -ForegroundColor Yellow
Write-Host "  python -m app.run --scenario k8s_rbac_permissions --llm mock --mode multi" -ForegroundColor Yellow
Write-Host ""
Write-Host ("The tar file is kept at: " + $tarPath) -ForegroundColor Yellow
Write-Host "Delete it manually if you no longer need it." -ForegroundColor Yellow
