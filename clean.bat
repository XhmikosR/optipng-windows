@echo off
setlocal

cd /d %~dp0

pushd src

for %%G in (
  "gifread"
  "gifread\test\"
  "libpng"
  "minitiff"
  "minitiff\test\"
  "opngreduc"
  "optipng"
  "optipng\test\"
  "pngxtern"
  "pnmio"
  "zlib"
) do call :clean %%G

popd

:end
endlocal
pause
exit /b

:clean
pushd "%~1"

for %%G in (
  "*.lib"
  "*.obj"
  "*.pdb"
  "*.exe"
  "*.exp"
  "*.dll"
  "*.res"
  "*.out"
) do (
  if exist "%%G" del "%%G"
)

popd
exit /b 0
