@echo off
cd /d "D:\New folder\safesphere"
:loop
echo Starting Flask...
.\.venv\Scripts\python.exe app.py >> logs\flask.log 2>>&1
echo Flask crashed. Restarting in 3 seconds...
timeout /t 3
goto loop

