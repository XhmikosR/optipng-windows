@echo off
setlocal

cd /d %~dp0

pushd src

call :clean "gifread"
call :clean "gifread\test\"
call :clean "libpng"
call :clean "minitiff"
call :clean "minitiff\test\"
call :clean "opngreduc"
call :clean "optipng"
call :clean "optipng\test\"
call :clean "pngxtern"
call :clean "pnmio"
call :clean "zlib"

popd

:end
endlocal
pause
exit /b

:clean
pushd "%~1"

if exist "*.lib" del "*.lib"
if exist "*.obj" del "*.obj"
if exist "*.pdb" del "*.pdb"
if exist "*.exe" del "*.exe"
if exist "*.exp" del "*.exp"
if exist "*.dll" del "*.dll"
if exist "*.res" del "*.res"
if exist "*.out" del "*.out"

popd
exit /b 0
