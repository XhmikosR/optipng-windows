@echo off
setlocal

cd /d %~dp0

rem add MSVC 64-bit in PATH
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

nmake /f build\visualc.mk
rem nmake -f build\visualc.mk test

:end
endlocal
rem pause
exit /b
