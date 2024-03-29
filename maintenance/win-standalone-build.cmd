@echo off
setlocal ENABLEDELAYEDEXPANSION

set project=pwman

set PATH=%PATH%;C:\WINDOWS;C:\WINDOWS\SYSTEM32
for /D %%f in ( "C:\PYTHON*" ) do set PATH=!PATH!;%%f
for /D %%f in ( "%USERPROFILE%\AppData\Local\Programs\Python\Python*" ) do set PATH=!PATH!;%%f;%%f\Scripts
set PATH=%PATH%;%ProgramFiles%\7-Zip


cd ..
if ERRORLEVEL 1 goto error_basedir


call :detect_version
if "%PROCESSOR_ARCHITECTURE%" == "x86" (
    set winprefix=win32
) else (
    set winprefix=win64
)
set distdir=%project%-%winprefix%-standalone-%version%
set sfxfile=%project%-%winprefix%-%version%.package.exe
set bindirname=%project%-bin
set bindir=%distdir%\%bindirname%
set builddir=%bindir%\build
set licensedirname=licenses
set licensedir=%distdir%\%licensedirname%


echo Building standalone Windows executable for %project%-%version%

call :prepare_env
call :build_cxfreeze
call :build_doc
call :copy_files
call :gen_startup_wrapper
call :make_archive

echo ---
echo finished
pause
exit /B 0


:detect_version
    py -c "import libpwman; print(libpwman.__version__)" > version.txt
    if ERRORLEVEL 1 goto error_version
    set /p version= < version.txt
    del version.txt
    exit /B 0


:prepare_env
    echo === Preparing distribution environment
    rd /S /Q build 2>NUL
    rd /S /Q %distdir% 2>NUL
    del %sfxfile% 2>NUL
    timeout /T 2 /NOBREAK >NUL
    mkdir %distdir%
    if ERRORLEVEL 1 goto error_prep
    mkdir %bindir%
    if ERRORLEVEL 1 goto error_prep
    exit /B 0


:build_cxfreeze
    echo === Creating the cx_Freeze distribution
    py setup.py ^
        build ^
        --build-base=%builddir% ^
        build_exe ^
        --build-exe=%bindir%
    if ERRORLEVEL 1 goto error_exe
    exit /B 0


:build_doc
    for %%i in (*.rst) do (
        echo Generating %%~ni.html from %%i ...
        py -m readme_renderer -o %%~ni.html %%i
        if ERRORLEVEL 1 goto error_doc
    )
    exit /B 0


:copy_files
    echo === Copying additional files
    mkdir %licensedir%
    if ERRORLEVEL 1 goto error_copy
    copy *.html %distdir%\
    if ERRORLEVEL 1 goto error_copy
    copy examplescript.py %distdir%\
    if ERRORLEVEL 1 goto error_copy
    xcopy /E /I doc %distdir%\doc
    if ERRORLEVEL 1 goto error_copy
    rmdir /S /Q %distdir%\doc\foreign-licenses
    if ERRORLEVEL 1 goto error_copy
    copy doc\foreign-licenses\*.txt %licensedir%\
    if ERRORLEVEL 1 goto error_copy
    copy COPYING %licensedir%\PWMAN-LICENSE.txt
    if ERRORLEVEL 1 goto error_copy
    rd /S /Q %builddir%
    if ERRORLEVEL 1 goto error_copy
    exit /B 0


:gen_startup_wrapper
    echo === Generating startup wrapper
    set wrapper=%distdir%\%project%.cmd
    echo @set PATH=%bindirname%;%bindirname%\lib;%bindirname%\platforms;%bindirname%\imageformats;%%PATH%% > %wrapper%
    echo @start %project%-bin\pwman.exe %%1 %%2 %%3 %%4 %%5 %%6 %%7 %%8 %%9 >> %wrapper%
    if ERRORLEVEL 1 goto error_wrapper
    exit /B 0


:make_archive
    echo === Creating the distribution archive
    7z a -mx=9 -sfx7z.sfx %sfxfile% %distdir%
    if ERRORLEVEL 1 goto error_7z
    exit /B 0


:error_basedir
echo FAILED to CD to base directory
goto error

:error_version
echo FAILED to detect version
goto error

:error_prep
echo FAILED to prepare environment
goto error

:error_exe
echo FAILED to build exe
goto error

:error_doc
echo FAILED to build doc
goto error

:error_copy
echo FAILED to copy files
goto error

:error_wrapper
echo FAILED to create wrapper
goto error

:error_7z
echo FAILED to create archive
goto error

:error
pause
exit 1
