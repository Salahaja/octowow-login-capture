@echo off
rem Polls normal.octowow.st's login port - every address it has - and beeps when it answers again.
rem NOTE: parenthesised blocks are avoided on purpose - cmd.exe expands variables while
rem parsing a ( ... ) block, and the client path contains a ')' which breaks that.
setlocal
set "SCRIPT=%~dp0Wait-ForOctoWow.ps1"
if not exist "%SCRIPT%" goto missing
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -HostName normal.octowow.st %*
goto end

:missing
echo Could not find Wait-ForOctoWow.ps1 next to this file.
pause

:end
endlocal
