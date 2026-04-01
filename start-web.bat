@echo off
@echo off
setlocal

set "REPO_ROOT=%~dp0"
set "SCAMURAI_DIR=%REPO_ROOT%Scamurai"
set "FRONTEND_DIR=%SCAMURAI_DIR%\frontend"
set "BACKEND_DIR=%SCAMURAI_DIR%"

set "PYTHON_EXE=%REPO_ROOT%.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

start "Scamurai Backend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location '%BACKEND_DIR%'; & '%PYTHON_EXE%' -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000"

start "Scamurai Frontend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location '%FRONTEND_DIR%'; if (-not (Test-Path 'node_modules')) { Write-Host 'Installing frontend dependencies...' -ForegroundColor Yellow; & 'npm.cmd' install }; & 'npm.cmd' run dev -- --host 127.0.0.1 --port 5173"

echo Started backend and frontend in separate windows.
