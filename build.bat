@echo off
setlocal
cd /d "%~dp0"

echo Installing dependencies...
py -m pip install --upgrade pip
if errorlevel 1 goto :error
py -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto :error

echo Building Dark-Souls-Remastered-Switch-to-PC-Converter.exe...
py -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name Dark-Souls-Remastered-Switch-to-PC-Converter dsr_switch_to_pc.py
if errorlevel 1 goto :error

echo.
echo Built: %CD%\dist\Dark-Souls-Remastered-Switch-to-PC-Converter.exe
pause
exit /b 0

:error
echo.
echo Build failed.
pause
exit /b 1
