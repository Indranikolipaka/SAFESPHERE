@echo off
echo Stopping SafeSphere services...

taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM ngrok.exe >nul 2>&1

echo SafeSphere server stopped.
pause
