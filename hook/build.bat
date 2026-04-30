@echo off
REM hook.dll build script (MSVC x86 32-bit)
REM
REM Onko: Visual Studio Developer Command Prompt'tan calistir, veya VS varsa
REM "x86 Native Tools Command Prompt for VS 20xx" ac, sonra:
REM   cd c:\Users\Ak\xxxxx\Desktop\s2\hook
REM   build.bat
REM
REM Cikti: hook.dll (TheRawServer.exe ile ayni klasore koy, sonra gg.dll yerine
REM kullan veya kendi injector'inla inject et)

cl /LD /EHsc /O2 /MD hook.cpp /link /OUT:hook.dll /MACHINE:X86 /SUBSYSTEM:WINDOWS

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ===========================================
    echo BUILD OK: hook.dll
    echo ===========================================
    dir hook.dll
) else (
    echo.
    echo BUILD FAILED — error %ERRORLEVEL%
    echo Visual Studio Developer Command Prompt acik mi?
)
