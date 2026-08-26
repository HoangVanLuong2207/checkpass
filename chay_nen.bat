@echo off
cd /d "%~dp0"
start "" /B python -X utf8 garena_api_test_chrome1.py --no-browser --timeout 20
echo Da khoi dong nen. Truy cap http://127.0.0.1:8766
echo Dung de dung: taskkill /F /IM python.exe
pause
