#!/bin/sh

read INPUT

#CRON ---
if echo "$INPUT" | grep -iq "cron"; then
    sed -i '/10.0.0.5/d' /etc/crontab
    echo "$(date) - SUCCESS: Malicious cron line removed" >> /var/ossec/logs/active-responses.log

#SUID ---
elif echo "$INPUT" | grep -iq "hidden_bash"; then
    rm -f /tmp/.hidden_bash
    echo "$(date) - SUCCESS: SUID binary deleted" >> /var/ossec/logs/active-responses.log
fi