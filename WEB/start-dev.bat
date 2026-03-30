@echo off
setlocal

set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

for /f "tokens=2 delims=," %%I in ('tasklist /fo csv /nh ^| findstr /i "python.exe node.exe cmd.exe"') do (
  rem Intentionally left blank to warm up tasklist parsing in cmd on some systems.
)

for %%P in (8000 5173) do (
  for /f "tokens=5" %%I in ('netstat -ano ^| findstr /r /c:":%%P .*LISTENING"') do (
    taskkill /PID %%I /T /F >nul 2>&1
  )
)

echo Starting backend and frontend...
echo.

start "Sentinel Backend" /D "%ROOT%backend" cmd /k ""%PY%" -m uvicorn app:app --port 8000"
start "Sentinel Frontend" /D "%ROOT%frontend" cmd /k "npm.cmd run dev -- --host 127.0.0.1"

echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173
echo.
echo Two terminal windows were opened.
endlocal
