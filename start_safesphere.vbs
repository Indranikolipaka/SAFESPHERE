Set shell = CreateObject("Wscript.Shell")

projectPath = "D:\\New folder\\safesphere"
pythonPath = projectPath & "\\.venv\\Scripts\\python.exe"
ngrokPath = "C:\\ngrok\\ngrok.exe"

' Change to project directory
shell.CurrentDirectory = projectPath

' Start Flask server silently with logging
shell.Run """" & pythonPath & """ app.py >> logs\\flask.log 2>>&1", 0

WScript.Sleep 5000  ' wait for Flask

' Start ngrok silently with logging
shell.Run """" & ngrokPath & """ http 5000 --basic-auth=admin:12345 >> logs\\ngrok.log 2>>&1", 0

MsgBox "SafeSphere server is now running silently in the background!", 64, "SafeSphere"
