@echo off
set SCRIPT_FOLDER=%~dp0
call %SCRIPT_FOLDER%venv\Scripts\activate
python %SCRIPT_FOLDER%emli.py %*
call %SCRIPT_FOLDER%venv\Scripts\deactivate