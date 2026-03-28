$ErrorActionPreference = "Stop"

function Write-Section {
  param([string]$Message)
  Write-Host ""
  Write-Host "== $Message ==" -ForegroundColor Cyan
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$pythonCmd = if (Test-Path $venvPython) { $venvPython } else { "python" }

Write-Section "Starting Sentinel Dev"
Write-Host "Backend dir : $backendDir"
Write-Host "Frontend dir: $frontendDir"
Write-Host "Python      : $pythonCmd"
Write-Host "Backend URL : http://localhost:8000"
Write-Host "Frontend URL: http://localhost:5173"
Write-Host ""
Write-Host "Press Ctrl+C to stop both services." -ForegroundColor Yellow

$backendJob = Start-Job -Name "sentinel-backend" -ScriptBlock {
  param($Dir, $Py)
  Set-Location $Dir
  & $Py -m uvicorn app:app --reload --port 8000 2>&1 | ForEach-Object {
    "[backend] $_"
  }
} -ArgumentList $backendDir, $pythonCmd

$frontendJob = Start-Job -Name "sentinel-frontend" -ScriptBlock {
  param($Dir)
  Set-Location $Dir
  & npm.cmd run dev 2>&1 | ForEach-Object {
    "[frontend] $_"
  }
} -ArgumentList $frontendDir

try {
  while ($true) {
    $lines = Receive-Job -Job $backendJob, $frontendJob -Keep
    foreach ($line in $lines) {
      Write-Host $line
    }

    if ($backendJob.State -in @("Failed", "Completed", "Stopped")) {
      Write-Host "Backend service exited with state: $($backendJob.State)" -ForegroundColor Red
      break
    }
    if ($frontendJob.State -in @("Failed", "Completed", "Stopped")) {
      Write-Host "Frontend service exited with state: $($frontendJob.State)" -ForegroundColor Red
      break
    }

    Start-Sleep -Milliseconds 200
  }
}
finally {
  Write-Section "Stopping Services"
  foreach ($job in @($backendJob, $frontendJob)) {
    if ($null -ne $job) {
      if ($job.State -eq "Running") {
        Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
      }
      Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue | Out-Null
      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
    }
  }
  Write-Host "Stopped."
}
