@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "REQ=%ROOT%requirements-hashes.txt"
set "PKGS=%ROOT%pkgs"

if not exist "%VENV%\Scripts\python.exe" (
  py -3 -m venv "%VENV%"
  if errorlevel 1 (
    python -m venv "%VENV%"
    if errorlevel 1 (
      echo Failed to create venv.
      exit /b 1
    )
  )
)

call "%VENV%\Scripts\activate.bat"
if errorlevel 1 exit /b 1

python -m pip install --upgrade pip
if errorlevel 1 exit /b 1

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
