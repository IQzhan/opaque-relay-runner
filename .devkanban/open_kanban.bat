@echo off
setlocal
REM Double-click Launcher for DevKanban Project Board
set "PROJ_DIR=%~dp0.."
for %%I in ("%PROJ_DIR%") do set "PROJ_DIR=%%~fI"
set "KB_SCRIPT=%DEVKANBAN_HOME%\kb.py"
if not exist "%KB_SCRIPT%" if exist "%PROJ_DIR%\kb.py" set "KB_SCRIPT=%PROJ_DIR%\kb.py"
if not exist "%KB_SCRIPT%" if exist "%PROJ_DIR%\..\DevKanban\kb.py" set "KB_SCRIPT=%PROJ_DIR%\..\DevKanban\kb.py"
python -B "%KB_SCRIPT%" --root "%PROJ_DIR%" ui
endlocal
