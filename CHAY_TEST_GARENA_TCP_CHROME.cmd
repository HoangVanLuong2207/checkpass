@echo off
cd /d "%~dp0"
python garena_tcp_login_chrome.py
if errorlevel 1 pause
