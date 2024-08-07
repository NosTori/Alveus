@echo off

SET work_dir=%~dp0
SET out_dir=%work_dir%

REM Run 32 bits environment.
call "%VCINSTALLDIR%\Auxiliary\Build\vcvars32.bat"

cl main.cpp Shell32.lib /std:c++20 /Z7 /link /OUT:"%out_dir%\Alveus.exe"
