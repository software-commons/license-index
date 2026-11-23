@echo off
setlocal
set "PYTHONPATH=%~dp0."
set "LICENSE_INDEX_PYTHON="
set "LICENSE_INDEX_PYTHON_ARGS="
for %%P in (python.exe) do set "LICENSE_INDEX_PYTHON=%%~$PATH:P"
if defined LICENSE_INDEX_PYTHON goto run
set "LICENSE_INDEX_PYTHON_ARGS=-3"
for %%P in (py.exe) do set "LICENSE_INDEX_PYTHON=%%~$PATH:P"
if not defined LICENSE_INDEX_PYTHON if exist "%SystemRoot%\py.exe" set "LICENSE_INDEX_PYTHON=%SystemRoot%\py.exe"
if defined LICENSE_INDEX_PYTHON goto run
echo license-index: Install Python 3.11 or later and add it to PATH. 1>&2
exit /b 1
:run
"%LICENSE_INDEX_PYTHON%" %LICENSE_INDEX_PYTHON_ARGS% -P -B -m tools.index %*
exit /b %errorlevel%
