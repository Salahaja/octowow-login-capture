@echo off
rem Polls the OctoWoW login server and beeps when it starts answering again.
rem NOTE: parenthesised blocks are avoided on purpose - cmd.exe expands variables while
rem parsing a ( ... ) block, and the client path contains a ')' which breaks that.
setlocal
set "SCRIPT=%~dp0Wait-ForOctoWow.ps1"
if not exist "%SCRIPT%" goto missing
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
goto end

:missing
echo Could not find Wait-ForOctoWow.ps1 next to this file.
pause

:end
endlocal
