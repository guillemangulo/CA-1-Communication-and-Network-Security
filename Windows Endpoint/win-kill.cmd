@echo off
taskkill /F /IM powershell.exe
echo %date% %time% - SUCCESS: PowerShell killed >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
