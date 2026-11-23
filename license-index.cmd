@echo off
setlocal
set "PYTHONPATH=%~dp0"
where py.exe >nul 2>nul
if errorlevel 1 (
  python -P -B -m tools.index %*
) else (
  py -3 -P -B -m tools.index %*
)
exit /b %errorlevel%
