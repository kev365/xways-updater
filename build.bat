@echo off
REM ============================================================================
REM  Build xways-updater.dll (x64) with MSVC cl.exe + rc.exe.
REM  Auto-bootstraps the VS environment if cl.exe isn't on PATH yet, so this
REM  works from a plain cmd.exe / PowerShell window. If you already opened the
REM  "x64 Native Tools Command Prompt for VS 2019/2022" the bootstrap is a no-op.
REM ============================================================================

setlocal EnableDelayedExpansion

REM --- Bootstrap VS x64 toolchain if needed ----------------------------------
REM Skipped if cl.exe is already on PATH (e.g. running from a Native Tools prompt).
where cl >nul 2>nul && goto :have_toolchain

set "VCVARS="
for %%V in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) do if not defined VCVARS if exist %%V set "VCVARS=%%~V"
if not defined VCVARS (
    echo ERROR: Could not find vcvars64.bat. Install the MSVC C++ build tools, or
    echo run this script from a "x64 Native Tools Command Prompt for VS 2019/2022".
    exit /b 1
)
echo Bootstrapping MSVC x64 environment from:
echo     !VCVARS!
REM Swallow vcvars's own stdout AND stderr — older vcvars64 scripts probe for
REM vswhere.exe and emit "'vswhere.exe' is not recognized" when it's absent.
call "!VCVARS!" >nul 2>nul
if errorlevel 1 (
    echo ERROR: vcvars64.bat reported failure.
    exit /b 1
)

:have_toolchain

set NAME=xways-updater
set OUT=%NAME%.dll
set CXXFLAGS=/nologo /std:c++17 /W3 /EHsc /O2 /utf-8 /DUNICODE /D_UNICODE
set LDFLAGS=/DLL /DEF:%NAME%.def /OUT:%OUT% /MACHINE:X64
set LIBS=User32.lib Comdlg32.lib Shell32.lib Ole32.lib Advapi32.lib Shlwapi.lib Crypt32.lib Winhttp.lib Version.lib OleAut32.lib Uuid.lib Gdi32.lib ComCtl32.lib

if exist *.obj del /q *.obj
if exist *.res del /q *.res

rc /nologo /fo %NAME%.res %NAME%.rc || goto :fail
cl %CXXFLAGS% /c %NAME%.cpp || goto :fail
link %LDFLAGS% %NAME%.obj %NAME%.res %LIBS% || goto :fail

echo.
echo Built: %OUT%

REM Project deployment convention: xtensions\<name>\<name>.dll — matches
REM X-Ways' built-in xtensions\ folder so the per-X-Tension subfolder can
REM be dropped straight into <X-Ways install>\xtensions\.
if not exist xtensions\%NAME% mkdir xtensions\%NAME%
copy /Y "%OUT%" "xtensions\%NAME%\%OUT%" >nul || goto :fail
if exist xways-updater.ico copy /Y xways-updater.ico "xtensions\%NAME%\xways-updater.ico" >nul
echo Deployed: xtensions\%NAME%\%OUT%

REM Remove the project-root DLL so it can't be accidentally loaded from
REM there. The cfg sidecar lands next to the loaded DLL; if X-Tensions.txt
REM still has a stale project-root path the load will simply fail and the
REM analyst re-adds via Tools ^> Run X-Tensions pointing at xtensions\%NAME%\%OUT%.
if exist "%OUT%" del /Q "%OUT%" 2>nul

exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1
