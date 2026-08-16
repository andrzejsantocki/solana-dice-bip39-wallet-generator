@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "REQ=%ROOT%requirements-hashes.txt"
set "PKGS=%ROOT%pkgs"

rem Wheels in pkgs/ are pinned for CPython 3.10 on Windows x64
rem (example: cffi-2.1.1-cp310-cp310-win_amd64.whl). Do not use generic py -3.
py -3.10 -c "import platform, struct, sys; assert struct.calcsize('P')*8 == 64 and platform.machine().lower() in ('amd64','x86_64'), 'Requires 64-bit Python 3.10 on Windows x64'; print(sys.version)"
if errorlevel 1 (
  echo Requires 64-bit CPython 3.10 for the bundled wheel set.
  exit /b 1
)

if not exist "%VENV%\Scripts\python.exe" (
  py -3.10 -m venv "%VENV%"
  if errorlevel 1 (
    echo Failed to create Python 3.10 venv.
    exit /b 1
  )
)

call "%VENV%\Scripts\activate.bat"
if errorlevel 1 exit /b 1

python -c "import sys; assert sys.version_info[:2] == (3, 10), 'Venv must use Python 3.10'; print(sys.version)"
if errorlevel 1 (
  echo Existing venv is not Python 3.10. Delete .venv and rerun setup_env.bat.
  exit /b 1
)

rem Do NOT upgrade pip here: that can contact the network.
rem Use the venv-bundled pip only, then install strictly from local pkgs/.

if not exist "%PKGS%" (
  echo Missing pkgs folder. Refusing online install.
  exit /b 1
)

pip install --no-index --find-links="%PKGS%" -r "%REQ%" --require-hashes
if errorlevel 1 exit /b 1

echo.
echo Ready. Venv: %VENV%
echo Run: %VENV%\Scripts\python.exe generate_wallet.py
endlocal
