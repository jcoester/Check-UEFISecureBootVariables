:: Created by github.com/cjee21
@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ps\Check-EventLog.ps1" %*
endlocal
pause
