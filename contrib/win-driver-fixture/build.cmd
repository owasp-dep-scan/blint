@echo off
setlocal
rem Build the driver-shaped test fixture. Run from a Visual Studio x64
rem developer command prompt; no WDK is required.
rem
rem   /GS-      no stack cookie, which would pull in the CRT
rem   /Gs...    no stack probe, same reason
rem   /kernel   is deliberately not used: it needs the WDK headers
rem   /DRIVER   emits a PE with the driver characteristics set

set OUT=%~1
if "%OUT%"=="" set OUT=blint_test_driver.sys

lib /nologo /def:"%~dp0ntoskrnl.def" /out:ntoskrnl.lib /machine:x64 || exit /b 1
cl /nologo /c /O2 /GS- /Gs1000000 /Zl "%~dp0ioctl_driver.c" /Fo:ioctl_driver.obj || exit /b 1
link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB ^
     /OUT:"%OUT%" ioctl_driver.obj ntoskrnl.lib || exit /b 1

echo Built %OUT%
