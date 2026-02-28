@echo off
net user malicious_win_user /active:no
echo %date% %time% - SUCCESS: User locked out >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
