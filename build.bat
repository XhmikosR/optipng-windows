@echo off
setlocal

cd /d "%~dp0"

rem add MSVC in PATH
call :SubVSPath
if not exist "%VS_PATH%" echo ERROR: Visual Studio NOT FOUND! & goto end

call "%VS_PATH%\Common7\Tools\VsDevCmd.bat" -arch=amd64

where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 echo ERROR: cmake NOT FOUND! & goto end

rem CFLAGS/LDFLAGS append to CMake's defaults
set CFLAGS=/W3 /D_CRT_SECURE_NO_DEPRECATE /D_CRT_NONSTDC_NO_DEPRECATE /D_CRT_SECURE_NO_WARNINGS
set LDFLAGS=/RELEASE
cmake -S . -B build -G "NMake Makefiles" -Wno-dev ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON
if %ERRORLEVEL% NEQ 0 goto end

cmake --build build
if %ERRORLEVEL% NEQ 0 goto end

if defined CI ctest --test-dir build --output-on-failure
if %ERRORLEVEL% NEQ 0 goto end

:end
endlocal
if not defined CI pause
exit /b %ERRORLEVEL%

:SubVSPath
for /f "delims=" %%A in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -property installationPath -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64') do set "VS_PATH=%%A"
exit /b
