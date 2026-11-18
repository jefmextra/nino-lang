@echo off
echo ============================================================================
echo [Nino Sovereign Bootstrap] Zero-Dependency Native Toolchain Installer
echo ============================================================================

where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [Error] System C11 compiler 'gcc' not found in PATH.
    echo Please install MinGW-w64 or MSYS2 GCC to bootstrap Nino from C11 seed.
    exit /b 1
)

if not exist bin mkdir bin

echo [1/2] Compiling C11 Bootstrap Seed (bootstrap\ninoc_seed.c)...
gcc -O3 -std=c11 bootstrap\ninoc_seed.c -o bin\ninoc_stage0.exe -lm -lgdi32 -luser32 -lbcrypt -lws2_32
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Stage 0 seed compilation failed.
    exit /b 1
)

echo [2/2] Self-Hosting Nino Compiler (compiler\ninoc.nino -^> bin\ninoc.exe)...
bin\ninoc_stage0.exe build compiler\ninoc.nino -o bin\ninoc.exe
if %ERRORLEVEL% NEQ 0 (
    echo [Error] Stage 1 self-hosting compilation failed.
    exit /b 1
)

del /q bin\ninoc_stage0.exe 2>nul
copy /y bin\ninoc.exe ninoc.exe >nul
copy /y bin\ninoc.exe compiler\ninoc.exe >nul
echo ============================================================================
echo [SUCCESS] Sovereign Native Compiler installed at: bin\ninoc.exe
echo ============================================================================
