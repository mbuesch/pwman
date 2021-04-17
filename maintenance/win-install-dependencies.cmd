@echo off
setlocal ENABLEDELAYEDEXPANSION


set PATH=%PATH%;C:\WINDOWS;C:\WINDOWS\SYSTEM32
for /D %%f in ( "C:\PYTHON*" ) do set PATH=!PATH!;%%f
for /D %%f in ( "%USERPROFILE%\AppData\Local\Programs\Python\Python*" ) do set PATH=!PATH!;%%f;%%f\Scripts


call :install wheel
if ERRORLEVEL 1 exit /B 1
call :install pywin32
if ERRORLEVEL 1 exit /B 1
call :install windows-curses
if ERRORLEVEL 1 exit /B 1
call :install pyreadline
if ERRORLEVEL 1 exit /B 1
call :install pyaes
if ERRORLEVEL 1 exit /B 1
call :install cx_Freeze
if ERRORLEVEL 1 exit /B 1
call :install readme_renderer
if ERRORLEVEL 1 exit /B 1


echo ---
echo finished successfully
pause
exit /B 0


:install
	echo Installing %1 ...
	pip3 install --upgrade %1
	if ERRORLEVEL 1 (
		echo FAILED to install %1
		pause
		exit /B 1
	)
	exit /B 0
