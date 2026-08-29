@echo off
cd /d "%~dp0"
start "" /B python -X utf8 garena_api_test_chrome1.py --no-browser --timeout 20 --port 5555
echo Da khoi dong nen. Truy cap http://127.0.0.1:5555
echo Muon them port: them --port SO_PORT vao dong lenh, vi du --port 5556 --port 6000
echo Dung de dung: taskkill /F /IM python.exe
pause
