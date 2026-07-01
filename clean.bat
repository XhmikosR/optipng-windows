@echo off
setlocal

cd /d "%~dp0"

if exist build rmdir /s /q build
if %ERRORLEVEL% NEQ 0 goto end

:end
endlocal
if not defined CI pause
exit /b %ERRORLEVEL%
