@echo off
setlocal EnableDelayedExpansion

set "REPO_ROOT=%~dp0"
set "SCAMURAI_DIR=%REPO_ROOT%Scamurai"
set "FRONTEND_DIR=%SCAMURAI_DIR%\frontend"
set "BACKEND_DIR=%SCAMURAI_DIR%"
set "VENV_DIR=%REPO_ROOT%.venv"
set "ENV_FILE=%REPO_ROOT%.env.local"

echo ========================================
echo Scamurai - Auto Setup and Run
echo ========================================
echo.

if exist "%ENV_FILE%" (
    echo Loading environment from .env.local
    for /f "usebackq tokens=* delims=" %%A in ("%ENV_FILE%") do (
        set "LINE=%%A"
        if defined LINE if not "!LINE:~0,1!"=="#" (
            for /f "tokens=1* delims==" %%B in ("!LINE!") do (
                if not "%%B"=="" set "%%B=%%C"
            )
        )
    )
)

echo.
echo [1/4] Setting up environment files...
if not exist "%ENV_FILE%" (
    echo Creating .env.local with default configuration...
    (
        echo # Frontend -^> backend URL for local dev
        echo VITE_API_BASE_URL=http://127.0.0.1:8000
        echo.
        echo # Backend CORS
        echo ALLOWED_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
        echo.
        echo # Supabase persistence
        echo SUPABASE_URL=https://moedjxitzecgwrillxjx.supabase.co
        echo SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1vZWRqeGl0emVjZ3dyaWxseGp4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUyMDEwMDMsImV4cCI6MjA5MDc3NzAwM30.I9GMGkRlKzAPflQVPm1zl9mEoO-YatW37G9_SirCHw0
        echo SUPABASE_TABLE=detection_results
    ) > "%ENV_FILE%"
    echo .env.local created with Supabase configuration.
) else (
    echo Environment file already exists.
)

echo.
echo [2/4] Setting up Python virtual environment...
if not exist "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%"
) else (
    echo Virtual environment already exists.
)

set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"
set "PIP_EXE=%VENV_DIR%\Scripts\pip.exe"
set "POWERSHELL_PYTHON_EXE=%PYTHON_EXE:\=\\%"
set "POWERSHELL_BACKEND_DIR=%BACKEND_DIR:\=\\%"
set "POWERSHELL_FRONTEND_DIR=%FRONTEND_DIR:\=\\%"

echo Installing Python dependencies...
"%PIP_EXE%" install -r "%SCAMURAI_DIR%\requirements.txt" --quiet

echo.
echo [3/4] Installing frontend dependencies...
if not exist "%FRONTEND_DIR%\node_modules" (
    echo Installing npm packages...
    cd /d "%FRONTEND_DIR%"
    call npm install
) else (
    echo npm packages already installed.
)

echo.
echo [4/4] Starting web servers...
echo Backend: http://127.0.0.1:8000
echo Frontend: http://127.0.0.1:5173
echo ========================================
echo.

start "Scamurai Backend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%POWERSHELL_BACKEND_DIR%'; & '%POWERSHELL_PYTHON_EXE%' -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8000"

start "Scamurai Frontend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%POWERSHELL_FRONTEND_DIR%'; & npm.cmd run dev -- --host 127.0.0.1 --port 5173 --force"

echo Started! Access the web at http://127.0.0.1:5173
pause
