@echo off
chcp 65001 >nul
title ATBM - Secure CV Transfer

echo ====================================================
echo   DE TAI 8: GUI CV AN TOAN CO KIEM TRA IP
echo   Dang khoi dong ca 2 server...
echo ====================================================

:: Chạy receiver.py trong cửa sổ riêng
start "RECEIVER - Port 5000" cmd /k "cd /d %~dp0 && python receiver.py"

:: Đợi 1 giây để receiver khởi động trước
timeout /t 1 /nobreak >nul

:: Chạy sender.py trong cửa sổ riêng
start "SENDER - Port 5001" cmd /k "cd /d %~dp0 && python sender.py"

:: Đợi 1 giây rồi mở trình duyệt
timeout /t 2 /nobreak >nul

echo.
echo   Receiver: http://localhost:5000
echo   Sender:   http://localhost:5001
echo.
echo   Dang mo trinh duyet...
echo ====================================================

:: Mở cả 2 trang web
start http://localhost:5000
start http://localhost:5001

echo.
echo   Da khoi dong xong! Dong cua so nay neu muon.
echo.
pause
