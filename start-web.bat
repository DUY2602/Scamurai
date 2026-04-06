@echo off
@echo off
setlocal EnableDelayedExpansion

set "REPO_ROOT=%~dp0"
set "SCAMURAI_DIR=%REPO_ROOT%Scamurai"
set "FRONTEND_DIR=%SCAMURAI_DIR%\frontend"
set "BACKEND_DIR=%SCAMURAI_DIR%"
set "ENV_FILE=%REPO_ROOT%.env.local"

if exist "%ENV_FILE%" (
    echo Loading local environment from .env.local
    for /f "usebackq tokens=* delims=" %%A in ("%ENV_FILE%") do (
        set "LINE=%%A"
        if defined LINE if not "!LINE:~0,1!"=="#" (
            for /f "tokens=1* delims==" %%B in ("!LINE!") do (
                if not "%%B"=="" set "%%B=%%C"
            )
        )
    )
)

if defined SUPABASE_URL (
    echo Effective Supabase URL: %SUPABASE_URL%
) else (
    echo Supabase persistence not configured for local run.
)

set "PYTHON_EXE=%REPO_ROOT%.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

start "Scamurai Backend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location '%BACKEND_DIR%'; & '%PYTHON_EXE%' -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000"

start "Scamurai Frontend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location '%FRONTEND_DIR%'; if (-not (Test-Path 'node_modules')) { Write-Host 'Installing frontend dependencies...' -ForegroundColor Yellow; & 'npm.cmd' install }; & 'npm.cmd' run dev -- --host 127.0.0.1 --port 5173 --force"

echo Started backend and frontend in separate windows.
