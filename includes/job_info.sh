#!/bin/bash

job_info()
{
echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m"

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31m[-] Cron jobs:\e[00m\n$cronjobs"
  echo -e "\n"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m[+] World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms"
  echo -e "\n"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2>/dev/null`
if [ "$crontabvalue" ]; then
  echo -e "\e[00;31m[-] Crontab contents:\e[00m\n$crontabvalue"
  echo -e "\n"
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31m[-] Anything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar"
  echo -e "\n"
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31m[-] Anacron jobs and associated file permissions:\e[00m\n$anacronjobs"
  echo -e "\n"
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31m[-] When were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab"
  echo -e "\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31m[-] Jobs held by all users:\e[00m\n$cronother"
  echo -e "\n"
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers="$(systemctl list-timers --all 2>/dev/null)"
  info=""
else
  systemdtimers="$(systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null)"
  # replace the info in the output with a hint towards thorough mode
  info="\e[2mEnable thorough tests to see inactive timers\e[00m"
fi
if [ "$systemdtimers" ]; then
  echo -e "\e[00;31m[-] Systemd timers:\e[00m\n$systemdtimers\n$info"
  echo -e "\n"
fi

}
