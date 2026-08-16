@echo off
setlocal
rem Build the driver-shaped test fixture. No WDK is required.
rem
rem Run it from a Visual Studio developer command prompt, or from an ordinary
rem one: if the compiler is not already on PATH, vswhere is used to find it.
rem
rem   /GS-      no stack cookie, which would pull in the CRT
rem   /Gs...    no stack probe, same reason
rem   /kernel   is deliberately not used: it needs the WDK headers
rem   /DRIVER   emits a PE with the driver characteristics set

set "OUT=%~1"
if "%OUT%"=="" set "OUT=blint_test_driver.sys"

where cl.exe >nul 2>&1
if errorlevel 1 call :find_msvc || exit /b 1

lib /nologo /def:"%~dp0ntoskrnl.def" /out:ntoskrnl.lib /machine:x64 || exit /b 1
cl /nologo /c /O2 /GS- /Gs1000000 /Zl "%~dp0ioctl_driver.c" /Fo:ioctl_driver.obj || exit /b 1
link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB ^
     /OUT:"%OUT%" ioctl_driver.obj ntoskrnl.lib || exit /b 1

echo Built %OUT%
exit /b 0

rem Locate and enter the MSVC environment.
rem
rem The installation path is not stable and must not be hard-coded: it carries
rem the product version, which is a year up to Visual Studio 2022
rem (...\2022\Enterprise) and an internal major version from 2026 onwards
rem (...\18\Enterprise). The edition varies too. vswhere.exe is the supported
rem way to resolve it, and its own location is fixed by design, so that is the
rem one path worth hard-coding.
:find_msvc
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found; run this from a VS developer command prompt.
    exit /b 1
)
set "VCVARS="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -products * ^
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
    -find VC\Auxiliary\Build\vcvars64.bat`) do set "VCVARS=%%i"
if not defined VCVARS (
    echo ERROR: no Visual Studio install with the x64 C++ toolset was found.
    exit /b 1
)
echo Using %VCVARS%
call "%VCVARS%" || exit /b 1
exit /b 0
