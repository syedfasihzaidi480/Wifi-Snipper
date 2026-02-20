@echo off
echo 🚀 WiFi Network Scanner Setup
echo ==============================

echo Creating virtual environment...
python -m venv .venv

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo ✅ Setup complete!
echo.
echo To run the scanner:
echo   1. Open PowerShell as Administrator
echo   2. Navigate to this folder
echo   3. Run: .venv\Scripts\activate
echo   4. Run: python advanced_network_scanner.py
echo.
pause