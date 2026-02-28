@echo off
del /F /Q "C:\temp\sam.hive"
echo %date% %time% - SUCCESS: SAM hive deleted >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
