@echo off
rem Captures traffic to the OctoWoW login server and prints a verdict. Elevates itself.
rem NOTE: parenthesised blocks are avoided on purpose - cmd.exe expands variables while
rem parsing a ( ... ) block, and the client path contains a ')' which breaks that.
setlocal
set "SCRIPT=%~dp0Capture-OctoWowLogin.ps1"
if not exist "%SCRIPT%" goto missing
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
goto end

:missing
echo Could not find Capture-OctoWowLogin.ps1 next to this file.
pause

:end
endlocal
