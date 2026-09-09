@echo off
chcp 65001 >nul
cd /d "%~dp0"
title AOV Master Server Coordinator

echo ========================================================
echo        🚀 KHOI DONG AOV MASTER SERVER (PORT 8761)
echo ========================================================
echo.
echo Giao dien web: http://127.0.0.1:8761
echo Nhan Ctrl+C de dung server.
echo.

start http://127.0.0.1:8761
python master_server.py --port 8761

pause
