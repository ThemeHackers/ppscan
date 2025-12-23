@echo off
setlocal

set "DIR=%~dp0"
set "PYTHONPATH=%DIR%src;%PYTHONPATH%"

if exist "%DIR%.venv\Scripts\activate.bat" (
    call "%DIR%.venv\Scripts\activate.bat"
) else (
    echo Warning: .venv not found or not created with standard layout.
    echo Trying global python...
)

python -m ppscan.cli %*

endlocal
