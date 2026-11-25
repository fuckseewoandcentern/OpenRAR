@echo off
setlocal enabledelayedexpansion

REM Optional argument: UI language baked into the binary (default en).
REM   build.bat
REM   build.bat zh
set "LANGPACK=en"
if not "%~1"=="" set "LANGPACK=%~1"
if not exist "lang\%LANGPACK%.txt" (
    echo [OpenRAR] No language pack lang\%LANGPACK%.txt
    exit /b 1
)

if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not exist build\generated mkdir build\generated

where python >nul 2>nul
if %ERRORLEVEL%==0 (
    python tools\embed_lang.py lang\en.txt lang\%LANGPACK%.txt build\generated\rar_lang_table.inc
) else (
    py -3 tools\embed_lang.py lang\en.txt lang\%LANGPACK%.txt build\generated\rar_lang_table.inc
)
if %ERRORLEVEL% NEQ 0 (
    echo [OpenRAR] Failed to embed language %LANGPACK%
    exit /b %ERRORLEVEL%
)

echo [OpenRAR] Compiling rar.exe ^(%LANGPACK%^) ...
cl.exe /nologo /std:c++17 /utf-8 /O2 /EHsc /W3 /I"include" /I"build\generated" ^
    src\rar_crypto.cpp ^
    src\rar_codec.cpp ^
    src\rar_archive.cpp ^
    src\rar_recover.cpp ^
    src\rar_os.cpp ^
    src\rar_i18n.cpp ^
    src\rar_cli.cpp ^
    src\main.cpp ^
    /Fo"build\\" /Fe"rar.exe" ^
    shell32.lib advapi32.lib

if %ERRORLEVEL% NEQ 0 (
    echo [OpenRAR] Build failed!
    exit /b %ERRORLEVEL%
)

copy /Y rar.exe unrar-free.exe >nul
echo [OpenRAR] Successfully built rar.exe and unrar-free.exe ^(%LANGPACK%^)
