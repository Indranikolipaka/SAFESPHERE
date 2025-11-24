@echo off
:: ===============================
:: SafeSphere Secure Run Script
:: ===============================

:: 1. Activate virtual environment
cd /d "D:\New folder\safesphere"
call .venv\Scripts\activate

:: 2. Start Flask app in a separate window
start cmd /k "python app.py"

:: 3. Wait a few seconds for Flask to start
timeout /t 5 /nobreak

:: 4. Start Ngrok with HTTPS, password protection, and optional subdomain
:: Replace admin:safesphere123 with your desired username:password
:: Replace safesphere with your reserved subdomain (remove --subdomain if not using)
start cmd /k "C:\ngrok\ngrok.exe http 5000 --auth=""rbvrr:rbvrr123"" 

:: 5. Optional: pause to keep batch window open
pause
