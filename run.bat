@echo off
rem thscan - start the app locally (Windows). Double-click this file.
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
if not exist .venv (
  echo [thscan] creating virtualenv...
  %PY% -m venv .venv || (echo Python 3.10+ is required: https://www.python.org/downloads/ & pause & exit /b 1)
)
call .venv\Scripts\activate.bat
echo [thscan] installing requirements...
pip install -q -r requirements.txt
if "%THSCAN_PORT%"=="" set THSCAN_PORT=8000
echo.
echo   thscan is running -^>  http://localhost:%THSCAN_PORT%
echo   (close this window to stop)
echo.
start "" http://localhost:%THSCAN_PORT%
uvicorn app.main:app --host 0.0.0.0 --port %THSCAN_PORT%
pause
