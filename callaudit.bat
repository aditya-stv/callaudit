@echo off
rem Android Forensic Auditor CLI launcher for Windows. Usage: callaudit COMMAND [options]
where py >NUL 2>NUL
if %ERRORLEVEL%==0 (
    py -3 "%~dp0cli.py" %*
) else (
    python "%~dp0cli.py" %*
)
exit /b %ERRORLEVEL%
