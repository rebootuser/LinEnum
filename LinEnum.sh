#!/bin/bash
#A simple script to enumerate local information from a Linux host
#version 0.3
#@oshearing
#@roo7break (further enhancements)

#option to store to a file
outfile="$1"

if [ "$outfile" ]; then
	echo -e "\n\e[00;30m#########################################################\e[00m" >> $outfile
	echo -e "\e[00;34mLocal Linux Enumeration & Privilege Escalation Script\e[00m" >> $outfile
	echo -e "\e[00;30m#########################################################\e[00m" >> $outfile
	echo -e "\e[00;30m# www.rebootuser.com\e[00m" >> $outfile
	echo -e "\e[00;30m# version 0.3\e[00m\n" >> $outfile
else
	echo -e "\n\e[00;30m#########################################################\e[00m"
	echo -e "\e[00;34mLocal Linux Enumeration & Privilege Escalation Script\e[00m"
	echo -e "\e[00;30m#########################################################\e[00m"
	echo -e "\e[00;30m# www.rebootuser.com\e[00m"
	echo -e "\e[00;30m# version 0.3\e[00m\n"
fi

#enter a single keyword that'll be used to search within *.conf, *.log & *.ini files.
if [ "$outfile" ]; then
	echo "Enter keywords (space separated) that'll be used to search in *.conf, *.log and *.ini files (e.g. password cred)" >> $outfile
	#accepts search keywords from commandline
	keyword="$2"
	echo -e "$keyword" >> $outfile
else
	echo "Enter keywords (space separated) that'll be used to search in *.conf, *.log and *.ini files (e.g. password cred)"
	#accepts search keywords from commandline
	read keyword
fi

who=`whoami`

if [ "$outfile" ]; then
	echo -e "\n" >> $outfile
	thedate=date
	echo -e "\e[00;30mScan started at: $thedate" >> $outfile
	echo -e "\e[00m\n" >> $outfile
else
	echo -e "\n"
	echo -e "\e[00;30mScan started at:"; date
	echo -e "\e[00m\n"
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### SYSTEM ##############################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### SYSTEM ##############################################\e[00m"
fi

unameinfo=`uname -a 2>/dev/null`

if [ "$outfile" ]; then
	if [ "$unameinfo" ]; then
	  echo -e "\e[00;31mKernel information:\e[00m\n$unameinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$unameinfo" ]; then
	  echo -e "\e[00;31mKernel information:\e[00m\n$unameinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

procver=`cat /proc/version 2>/dev/null`

if [ "$outfile" ];then
	if [ "$procver" ]; then
	  echo -e "\e[00;31mKernel information (continued):\e[00m\n$procver" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$procver" ]; then
	  echo -e "\e[00;31mKernel information (continued):\e[00m\n$procver"
	  echo -e "\n"
	else 
	  :
	fi
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`

if [ "$outfile" ];then
	if [ "$release" ]; then
	  echo -e "\e[00;31mSpecific release information:\e[00m\n$release" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$release" ]; then
		echo -e "\e[00;31mSpecific release information:\e[00m\n$release"
		echo -e "\n"
	else 
		:
	fi
fi

hostnamed=`hostname 2>/dev/null`

if [ "$outfile" ];then
	if [ "$hostnamed" ]; then
	  echo -e "\e[00;31mHostname:\e[00m\n$hostnamed" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$hostnamed" ]; then
	  echo -e "\e[00;31mHostname:\e[00m\n$hostnamed"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### USER/GROUP ##########################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### USER/GROUP ##########################################\e[00m"
fi

currusr=`id 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$currusr" ]; then
	  echo -e "\e[00;31mCurrent user/group info:\e[00m\n$currusr" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$currusr" ]; then
	  echo -e "\e[00;31mCurrent user/group info:\e[00m\n$currusr"
	  echo -e "\n"
	else 
	  :
	fi
fi

grpinfo=`getent group $who 2>/dev/null`
if [ "$outfile" ];then
	if [ "$grpinfo" ]; then
	  echo -e "\e[00;31mAll members of 'our' group(s):\e[00m\n$grpinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$grpinfo" ]; then
	  echo -e "\e[00;31mAll members of 'our' group(s):\e[00m\n$grpinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

lastlogedonusrs=`lastlog |grep -v "Never" 2>/dev/null`
if [ "$outfile" ];then
	if [ "$lastlogedonusrs" ]; then
	  echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m\n$lastlogedonusrs" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$lastlogedonusrs" ]; then
	  echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m\n$lastlogedonusrs"
	  echo -e "\n"
	else 
	  :
	fi
fi

usrsinfo=`cat /etc/passwd | cut -d ":" -f 1,2,3,4 2>/dev/null`
if [ "$outfile" ];then
	if [ "$usrsinfo" ]; then
	  echo -e "\e[00;31mAll users and uid/gid info:\e[00m\n$usrsinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$usrsinfo" ]; then
	  echo -e "\e[00;31mAll users and uid/gid info:\e[00m\n$usrsinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$hashesinpasswd" ]; then
	  echo -e "\e[00;33mIt looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$hashesinpasswd" ]; then
	  echo -e "\e[00;33mIt looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd"
	  echo -e "\n"
	else 
	  :
	fi
fi

#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$outfile" ]; then
	if [ "$readpasswd" ]; then
	  echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$readpasswd" ]; then
	  echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd"
	  echo -e "\n"
	else 
	  :
	fi
fi

readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$readshadow" ]; then
	  echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$readshadow" ]; then
	  echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow"
	  echo -e "\n"
	else 
	  :
	fi
fi

readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$readmasterpasswd" ]; then
	  echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$readmasterpasswd" ]; then
	  echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd"
	  echo -e "\n"
	else 
	  :
	fi
fi

#all root accounts (uid 0)
if [ "$outfile" ]; then
	echo -e "\e[00;31mSuper user account(s):\e[00m" >> $outfile; grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1 }' >> $outfile
	echo -e "\n" >> $outfile
else
	echo -e "\e[00;31mSuper user account(s):\e[00m"; grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'
	echo -e "\n"
fi

#pull out vital sudoers info
sudoers=`cat /etc/sudoers 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$sudoers" ]; then
	  echo -e "\e[00;31mSudoers configuration:\e[00m" >> $outfile; cat /etc/sudoers 2>/dev/null | grep -A 1 "User priv" >> $outfile; cat /etc/sudoers | grep -A 1 "Allow" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$sudoers" ]; then
	  echo -e "\e[00;31mSudoers configuration:\e[00m"; cat /etc/sudoers 2>/dev/null | grep -A 1 "User priv"; cat /etc/sudoers | grep -A 1 "Allow"
	  echo -e "\n"
	else 
	  :
	fi
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$sudoperms" ]; then
	  echo -e "\e[00;33mWe can sudo without supplying a password!\e[00m\n$sudoperms" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$sudoperms" ]; then
	  echo -e "\e[00;33mWe can sudo without supplying a password!\e[00m\n$sudoperms"
	  echo -e "\n"
	else 
	  :
	fi
fi

#known 'good' breakout binaries
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$sudopwnage" ]; then
	  echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$sudopwnage" ]; then
	  echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage"
	  echo -e "\n"
	else 
	  :
	fi
fi

rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$rthmdir" ]; then
	  echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$rthmdir" ]; then
	  echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir"
	  echo -e "\n"
	else 
	  :
	fi
fi

homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$homedirperms" ]; then
	  echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$homedirperms" ]; then
	  echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms"
	  echo -e "\n"
	else 
	  :
	fi
fi

wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$wrfileshm" ]; then
	  echo -e "\e[00;31mWorld-readable files within /home:\e[00m\n$wrfileshm" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$wrfileshm" ]; then
	  echo -e "\e[00;31mWorld-readable files within /home:\e[00m\n$wrfileshm"
	  echo -e "\n"
	else 
	  :
	fi
fi

homedircontents=`ls -ahl ~ 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$homedircontents" ]; then
	  echo -e "\e[00;31mHome directory contents:\e[00m\n$homedircontents" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$homedircontents" ]; then
	  echo -e "\e[00;31mHome directory contents:\e[00m\n$homedircontents"
	  echo -e "\n"
	else 
	  :
	fi
fi

sshfiles=`find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la`
if [ "$outfile" ];then
	if [ "$sshfiles" ]; then
	  echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$sshfiles" ]; then
	  echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles"
	  echo -e "\n"
	else 
	  :
	fi
fi

sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$outfile" ]; then
	if [ "$sshrootlogin" = "yes" ]; then
	  echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m" >> $outfile; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$sshrootlogin" = "yes" ]; then
	  echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m"; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "%outfile" ]; then
	echo -e "\e[00;34m### ENVIRONMENTAL #######################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### ENVIRONMENTAL #######################################\e[00m"
fi

pathinfo=`echo $PATH 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$pathinfo" ]; then
	  echo -e "\e[00;31mPath information:\e[00m\n$pathinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$pathinfo" ]; then
	  echo -e "\e[00;31mPath information:\e[00m\n$pathinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$shellinfo" ]; then
	  echo -e "\e[00;31mAvailable shells:\e[00m\n$shellinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$shellinfo" ]; then
	  echo -e "\e[00;31mAvailable shells:\e[00m\n$shellinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### JOBS/TASKS ##########################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### JOBS/TASKS ##########################################\e[00m"
fi

cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$cronjobs" ]; then
	  echo -e "\e[00;31mCron jobs:\e[00m\n$cronjobs" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$cronjobs" ]; then
	  echo -e "\e[00;31mCron jobs:\e[00m\n$cronjobs"
	  echo -e "\n"
	else 
	  :
	fi
fi

cronjobwwperms=`find /etc/cron* -perm -0002 -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$outfile" ]; then
	if [ "$cronjobwwperms" ]; then
	  echo -e "\e[00;33m***World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$cronjobwwperms" ]; then
	  echo -e "\e[00;33m***World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms"
	  echo -e "\n"
	else 
	  :
	fi
fi

crontab=`cat /etc/crontab 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$crontab" ]; then
	  echo -e "\e[00;31mCrontab contents:\e[00m\n$crontab" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$crontab" ]; then
	  echo -e "\e[00;31mCrontab contents:\e[00m\n$crontab"
	  echo -e "\n"
	else 
	  :
	fi
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$crontabvar" ]; then
	  echo -e "\e[00;31mAnything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$crontabvar" ]; then
	  echo -e "\e[00;31mAnything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar"
	  echo -e "\n"
	else 
	  :
	fi
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$anacronjobs" ]; then
	  echo -e "\e[00;31mAnacron jobs and associated file permissions:\e[00m\n$anacronjobs" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$anacronjobs" ]; then
	  echo -e "\e[00;31mAnacron jobs and associated file permissions:\e[00m\n$anacronjobs"
	  echo -e "\n"
	else 
	  :
	fi
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$anacrontab" ]; then
	  echo -e "\e[00;31mWhen were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$anacrontab" ]; then
	  echo -e "\e[00;31mWhen were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab"
	  echo -e "\n"
	else 
	  :
	fi
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$cronother" ]; then
	  echo -e "\e[00;31mJobs held by all users:\e[00m\n$cronother" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$cronother" ]; then
	  echo -e "\e[00;31mJobs held by all users:\e[00m\n$cronother"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### NETWORKING  ##########################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### NETWORKING  ##########################################\e[00m"
fi

nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$nicinfo" ]; then
	  echo -e "\e[00;31mNetwork & IP info:\e[00m\n$nicinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$nicinfo" ]; then
	  echo -e "\e[00;31mNetwork & IP info:\e[00m\n$nicinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

nsinfo=`cat /etc/resolv.conf 2>/dev/null | grep "nameserver"`
if [ "$outfile" ]; then
	if [ "$nsinfo" ]; then
	  echo -e "\e[00;31mNameserver(s):\e[00m\n$nsinfo" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$nsinfo" ]; then
	  echo -e "\e[00;31mNameserver(s):\e[00m\n$nsinfo"
	  echo -e "\n"
	else 
	  :
	fi
fi

defroute=`route 2>/dev/null | grep default`
if [ "$outfile" ]; then
	if [ "$defroute" ]; then
	  echo -e "\e[00;31mDefault route:\e[00m\n$defroute" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$defroute" ]; then
	  echo -e "\e[00;31mDefault route:\e[00m\n$defroute"
	  echo -e "\n"
	else 
	  :
	fi
fi

tcpservs=`netstat -antp 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$tcpservs" ]; then
	  echo -e "\e[00;31mListening TCP:\e[00m\n$tcpservs" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$tcpservs" ]; then
	  echo -e "\e[00;31mListening TCP:\e[00m\n$tcpservs"
	  echo -e "\n"
	else 
	  :
	fi
fi

udpservs=`netstat -anup 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$udpservs" ]; then
	  echo -e "\e[00;31mListening UDP:\e[00m\n$udpservs" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$udpservs" ]; then
	  echo -e "\e[00;31mListening UDP:\e[00m\n$udpservs"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### SERVICES #############################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### SERVICES #############################################\e[00m"
fi

psaux=`ps aux 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$psaux" ]; then
	  echo -e "\e[00;31mRunning processes:\e[00m\n$psaux" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$psaux" ]; then
	  echo -e "\e[00;31mRunning processes:\e[00m\n$psaux"
	  echo -e "\n"
	else 
	  :
	fi
fi

#lookup process binary path and permissisons
procperm=`ps aux | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++'`
if [ "$outfile" ]; then
	if [ "$procperm" ]; then
	  echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m\n$procperm" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$procperm" ]; then
	  echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m\n$procperm"
	  echo -e "\n"
	else 
	  :
	fi
fi

inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$inetdread" ]; then
	  echo -e "\e[00;31mContents of /etc/inetd.conf:\e[00m\n$inetdread" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$inetdread" ]; then
	  echo -e "\e[00;31mContents of /etc/inetd.conf:\e[00m\n$inetdread"
	  echo -e "\n"
	else 
	  :
	fi
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`cat /etc/inetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$inetdbinperms" ]; then
	  echo -e "\e[00;31mThe related inetd binary permissions:\e[00m\n$inetdbinperms" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$inetdbinperms" ]; then
	  echo -e "\e[00;31mThe related inetd binary permissions:\e[00m\n$inetdbinperms" 
	  echo -e "\n"
	else 
	  :
	fi
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$xinetdread" ]; then
	  echo -e "\e[00;31mContents of /etc/xinetd.conf:\e[00m\n$xinetdread" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$xinetdread" ]; then
	  echo -e "\e[00;31mContents of /etc/xinetd.conf:\e[00m\n$xinetdread"
	  echo -e "\n"
	else 
	  :
	fi
fi

xinetdincd=`cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$xinetdincd" ]; then
	  echo -e "\e[00;31m/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null  >> $outfile
	  echo -e "\n"  >> $outfile
	else 
	  :
	fi
else
	if [ "$xinetdincd" ]; then
	  echo -e "\e[00;31m/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null
	  echo -e "\n"
	else 
	  :
	fi
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`cat /etc/xinetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$xinetdbinperms" ]; then
	  echo -e "\e[00;31mThe related xinetd binary permissions:\e[00m\n$xinetdbinperms";  >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$xinetdbinperms" ]; then
	  echo -e "\e[00;31mThe related xinetd binary permissions:\e[00m\n$xinetdbinperms"; 
	  echo -e "\n"
	else 
	  :
	fi
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$initdread" ]; then
	  echo -e "\e[00;31m/etc/init.d/ binary permissions:\e[00m\n$initdread" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi  
else
	if [ "$initdread" ]; then
	  echo -e "\e[00;31m/etc/init.d/ binary permissions:\e[00m\n$initdread"
	  echo -e "\n"
	else 
	  :
	fi  
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$rcdread" ]; then
	  echo -e "\e[00;31m/etc/rc.d/init.d binary permissions:\e[00m\n$rcdread" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$rcdread" ]; then
	  echo -e "\e[00;31m/etc/rc.d/init.d binary permissions:\e[00m\n$rcdread"
	  echo -e "\n"
	else 
	  :
	fi
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$usrrcdread" ]; then
	  echo -e "\e[00;31m/usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$usrrcdread" ]; then
	  echo -e "\e[00;31m/usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### SOFTWARE #############################################\e[00m" >> $outfile
else
	echo -e "\e[00;34m### SOFTWARE #############################################\e[00m"
fi

sudover=`sudo -V | grep "Sudo version" 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$sudover" ]; then
	  echo -e "\e[00;31mSudo version:\e[00m\n$sudover" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$sudover" ]; then
	  echo -e "\e[00;31mSudo version:\e[00m\n$sudover"
	  echo -e "\n"
	else 
	  :
	fi
fi

mysqlver=`mysql --version 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$mysqlver" ]; then
	  echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$mysqlver" ]; then
	  echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver"
	  echo -e "\n"
	else 
	  :
	fi
fi

mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$mysqlconnect" ]; then
	  echo -e "\e[00;33m***We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$mysqlconnect" ]; then
	  echo -e "\e[00;33m***We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect"
	  echo -e "\n"
	else 
	  :
	fi
fi

mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$mysqlconnectnopass" ]; then
	  echo -e "\e[00;33m***We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$mysqlconnectnopass" ]; then
	  echo -e "\e[00;33m***We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass"
	  echo -e "\n"
	else 
	  :
	fi
fi

postgver=`psql -V 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$postgver" ]; then
	  echo -e "\e[00;31mPostgres version:\e[00m\n$postgver" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$postgver" ]; then
	  echo -e "\e[00;31mPostgres version:\e[00m\n$postgver"
	  echo -e "\n"
	else 
	  :
	fi
fi

postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$outfile" ]; then
	if [ "$postcon1" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$postcon1" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1"
	  echo -e "\n"
	else 
	  :
	fi
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$outfile" ]; then
	if [ "$postcon11" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$postcon11" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11"
	  echo -e "\n"
	else 
	  :
	fi
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$outfile" ]; then
	if [ "$postcon2" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$postcon2" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2"
	  echo -e "\n"
	else 
	  :
	fi
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$outfile" ]; then
	if [ "$postcon22" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$postcon22" ]; then
	  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22"
	  echo -e "\n"
	else 
	  :
	fi
fi

apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$apachever" ]; then
	  echo -e "\e[00;31mApache version:\e[00m\n$apachever" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$apachever" ]; then
	  echo -e "\e[00;31mApache version:\e[00m\n$apachever"
	  echo -e "\n"
	else 
	  :
	fi
fi

apacheusr=`cat /etc/apache2/envvars 2>/dev/null |grep -i 'user\|group' |awk '{sub(/.*\export /,"")}1'`
if [ "$outfile" ]; then
	if [ "$apacheusr" ]; then
	  echo -e "\e[00;31mApache user configuration:\e[00m\n$apacheusr" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$apacheusr" ]; then
	  echo -e "\e[00;31mApache user configuration:\e[00m\n$apacheusr"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;34m### INTERESTING FILES ####################################\e[00m" >> $outfile
	echo -e "\e[00;31mUseful file locations:\e[00m" >> $outfile;which nc 2>/dev/null >> $outfile; which netcat 2>/dev/null >> $outfile; which wget 2>/dev/null >> $outfile; which nmap 2>/dev/null >> $outfile; which gcc 2>/dev/null >> $outfile
	echo -e "\n" >> $outfile
	echo -e "\e[00;31mCan we read/write sensitive files:\e[00m" >> $outfile;ls -la /etc/passwd 2>/dev/null >> $outfile; ls -la /etc/group 2>/dev/null >> $outfile; ls -la /etc/profile 2>/dev/null >> $outfile; ls -la /etc/shadow 2>/dev/null >> $outfile; ls -la /etc/master.passwd 2>/dev/null >> $outfile
	echo -e "\n" >> $outfile
else
	echo -e "\e[00;34m### INTERESTING FILES ####################################\e[00m"
	echo -e "\e[00;31mUseful file locations:\e[00m"      ;which nc 2>/dev/null; which netcat 2>/dev/null; which wget 2>/dev/null; which nmap 2>/dev/null; which gcc 2>/dev/null
	echo -e "\n"
	echo -e "\e[00;31mCan we read/write sensitive files:\e[00m"	;ls -la /etc/passwd 2>/dev/null; ls -la /etc/group 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null
	echo -e "\n"
fi

findsuid=`find / -perm -4000 -type f 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$findsuid" ]; then
	  echo -e "\e[00;31mSUID files:\e[00m\n$findsuid" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$findsuid" ]; then
	  echo -e "\e[00;31mSUID files:\e[00m\n$findsuid"
	  echo -e "\n"
	else 
	  :
	fi
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la`
if [ "$outfile" ]; then
	if [ "$intsuid" ]; then
	  echo -e "\e[00;33m***Possibly interesting SUID files:\e[00m\n$intsuid" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$intsuid" ]; then
	  echo -e "\e[00;33m***Possibly interesting SUID files:\e[00m\n$intsuid"
	  echo -e "\n"
	else 
	  :
	fi
fi

wwsuid=`find / -perm -4007 -type f 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$wwsuid" ]; then
	  echo -e "\e[00;31mWorld-writable SUID files:\e[00m\n$wwsuid" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$wwsuid" ]; then
	  echo -e "\e[00;31mWorld-writable SUID files:\e[00m\n$wwsuid"
	  echo -e "\n"
	else 
	  :
	fi
fi

wwsuidrt=`find / -uid 0 -perm -4007 -type f 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$wwsuidrt" ]; then
	  echo -e "\e[00;31mWorld-writable SUID files owned by root:\e[00m\n$wwsuidrt" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$wwsuidrt" ]; then
	  echo -e "\e[00;31mWorld-writable SUID files owned by root:\e[00m\n$wwsuidrt"
	  echo -e "\n"
	else 
	  :
	fi
fi

findguid=`find / -perm -2000 -type f 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$findguid" ]; then
	  echo -e "\e[00;31mGUID files:\e[00m\n$findguid" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$findguid" ]; then
	  echo -e "\e[00;31mGUID files:\e[00m\n$findguid"
	  echo -e "\n"
	else 
	  :
	fi
fi

#list of 'interesting' guid files - feel free to make additions
intguid=`find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la`
if [ "$outfile" ]; then
	if [ "$intguid" ]; then
	  echo -e "\e[00;33m***Possibly interesting GUID files:\e[00m\n$intguid" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$intguid" ]; then
	  echo -e "\e[00;33m***Possibly interesting GUID files:\e[00m\n$intguid"
	  echo -e "\n"
	else 
	  :
	fi
fi

wwguid=`find / -perm -2007 -type f 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$wwguid" ]; then
	  echo -e "\e[00;31mWorld-writable GUID files:\e[00m\n$wwguid" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$wwguid" ]; then
	  echo -e "\e[00;31mWorld-writable GUID files:\e[00m\n$wwguid"
	  echo -e "\n"
	else 
	  :
	fi
fi

wwguidrt=`find / -uid 0 -perm -2007 -type f 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$wwguidrt" ]; then
	  echo -e "\e[00;31mAWorld-writable GUID files owned by root:\e[00m\n$wwguidrt" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$wwguidrt" ]; then
	  echo -e "\e[00;31mAWorld-writable GUID files owned by root:\e[00m\n$wwguidrt"
	  echo -e "\n"
	else 
	  :
	fi
fi

#list all world-writable files excluding /proc
wwfiles=`find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$wwfiles" ]; then
	  echo -e "\e[00;31mWorld-writable files (excluding /proc):\e[00m\n$wwfiles" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$wwfiles" ]; then
	  echo -e "\e[00;31mWorld-writable files (excluding /proc):\e[00m\n$wwfiles"
	  echo -e "\n"
	else 
	  :
	fi
fi

usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$outfile" ]; then
	if [ "$usrplan" ]; then
	  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$usrplan" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$usrplan" ]; then
	  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$usrplan"
	  echo -e "\n"
	else 
	  :
	fi
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$outfile" ]; then
	if [ "$bsdusrplan" ]; then
	  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$bsdusrplan" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$bsdusrplan" ]; then
	  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$bsdusrplan"
	  echo -e "\n"
	else 
	  :
	fi
fi
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$outfile" ]; then
	if [ "$rhostsusr" ]; then
	  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$rhostsusr" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$rhostsusr" ]; then
	  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$rhostsusr"
	  echo -e "\n"
	else 
	  :
	fi
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$outfile" ]; then
	if [ "$bsdrhostsusr" ]; then
	  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$bsdrhostsusr" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$bsdrhostsusr" ]; then
	  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$bsdrhostsusr"
	  echo -e "\n"
	else 
	  :
	fi
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$outfile" ]; then
	if [ "$rhostssys" ]; then
	  echo -e "\e[00;31mHosts.equiv file details and file contents: \e[00m\n$rhostssys" >> $outfile
	  echo -e "\n" >> $outfile
	  else 
	  :
	fi
else
	if [ "$rhostssys" ]; then
	  echo -e "\e[00;31mHosts.equiv file details and file contents: \e[00m\n$rhostssys"
	  echo -e "\n"
	  else 
	  :
	fi
fi

nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$nfsexports" ]; then
	  echo -e "\e[00;31mNFS config details: \e[00m\n$nfsexports" >> $outfile
	  echo -e "\n" >> $outfile
	  else 
	  :
	fi
else
	if [ "$nfsexports" ]; then
	  echo -e "\e[00;31mNFS config details: \e[00m\n$nfsexports"
	  echo -e "\n"
	  else 
	  :
	fi
fi

fstab=`cat /etc/fstab 2>/dev/null |grep username |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1'| xargs -r echo username:; cat /etc/fstab 2>/dev/null |grep password |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1'| xargs -r echo password:; cat /etc/fstab 2>/dev/null |grep domain |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1'| xargs -r echo domain:`
if [ "$outfile" ]; then
	if [ "$fstab" ]; then
	  echo -e "\e[00;33m***Looks like there are credentials in /etc/fstab!\e[00m\n$fstab" >> $outfile
	  echo -e "\n" >> $outfile
	  else 
	  :
	fi
else
	if [ "$fstab" ]; then
	  echo -e "\e[00;33m***Looks like there are credentials in /etc/fstab!\e[00m\n$fstab"
	  echo -e "\n"
	  else 
	  :
	fi
fi

fstabcred=`cat /etc/fstab 2>/dev/null |grep cred |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1'| xargs -I{} sh -c 'ls -la {}; cat {}'`
if [ "$outfile" ]; then
	if [ "$fstabcred" ]; then
		echo -e "\e[00;33m***/etc/fstab contains a credentials file!\e[00m\n$fstabcred" >> $outfile
		echo -e "\n" >> $outfile
		else
		:
	fi
else
	if [ "$fstabcred" ]; then
		echo -e "\e[00;33m***/etc/fstab contains a credentials file!\e[00m\n$fstabcred"
		echo -e "\n"
		else
		:
	fi
fi

#Search function for optimising searches and to support multiple keywords
function searches(){
	#keyword that will be searched
	searchme=$1
	#file type that will be searched (*.conf, *.log, etc.)
	searchfile=$2
	#depth for search
	depth=$3
	if [ "$outfile" ]; then
		if [ "$searchme" = "" ]; then
			echo -e "Can't search $searchfile files as no keyword was entered\n" >> $outfile
		else
			searchkey=`find / -maxdepth $depth -name $searchfile -type f -exec grep -Hn $searchme {} \; 2>/dev/null`
			if [ "$searchkey" ]; then
				echo -e "\e[00;32mSearch keyword ($searchme) in .conf files (recursive $depth levels - output format filepath:identified line number where keyword appears):\e[00m\n$searchkey" >> $outfile
				echo -e "\n" >> $outfile
			else
				echo -e "\e[00;31mSearch keyword ($keyword) in .conf files (recursive 4 levels):\e[00m" >> $outfile
				echo -e "'$searchme' not found in any $searchfile files" >> $outfile
				echo -e "\n" >> $outfile
			fi
		fi
	else
		if [ "$searchme" = "" ]; then
			echo -e "Can't search $searchfile files as no keyword was entered\n"
		else
			searchkey=`find / -maxdepth $depth -name $searchfile -type f -exec grep -Hn $searchme {} \; 2>/dev/null`
			if [ "$searchkey" ]; then
				echo -e "\e[00;32mSearch keyword ($searchme) in .conf files (recursive $depth levels - output format filepath:identified line number where keyword appears):\e[00m\n$searchkey"
				echo -e "\n"
			else
				echo -e "\e[00;31mSearch keyword ($keyword) in .conf files (recursive 4 levels):\e[00m"
				echo -e "'$searchme' not found in any $searchfile files"
				echo -e "\n"
			fi
		fi
	fi
}

IFS=' ' read -a all_keywords <<< "${keyword}"


#use supplied keyword/s and selected file types for potentional matches - output will show line number within relevant file path where a match has been located
for words in "${all_keywords[@]}"
do
	#call search function with arguments keyword, file extension (*.extension) and depth
	searches "$words" *.conf 4
	searches "$words" *.log 2
	searches "$words" *.ini 2
done

allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$allconf" ]; then
	  echo -e "\e[00;31mAll *.conf files in /etc (recursive 1 level):\e[00m\n$allconf" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$allconf" ]; then
	  echo -e "\e[00;31mAll *.conf files in /etc (recursive 1 level):\e[00m\n$allconf" 
	  echo -e "\n"
	else 
	  :
	fi
fi

usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$usrhist" ]; then
	  echo -e "\e[00;31mCurrent user's history files:\e[00m\n$usrhist" >> $outfile 
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$usrhist" ]; then
	  echo -e "\e[00;31mCurrent user's history files:\e[00m\n$usrhist" 
	  echo -e "\n"
	else 
	  :
	fi
fi

roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$roothist" ]; then
	  echo -e "\e[00;33m***Root's history files are accessible!\e[00m\n$roothist" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$roothist" ]; then
	  echo -e "\e[00;33m***Root's history files are accessible!\e[00m\n$roothist"
	  echo -e "\n"
	else 
	  :
	fi
fi

readmail=`ls -la /var/mail 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$readmail" ]; then
	  echo -e "\e[00;31mAny interesting mail in /var/mail:\e[00m\n$readmail" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$readmail" ]; then
	  echo -e "\e[00;31mAny interesting mail in /var/mail:\e[00m\n$readmail"
	  echo -e "\n"
	else 
	  :
	fi
fi

readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$outfile" ]; then
	if [ "$readmailroot" ]; then
	  echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot" >> $outfile
	  echo -e "\n" >> $outfile
	else 
	  :
	fi
else
	if [ "$readmailroot" ]; then
	  echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot"
	  echo -e "\n"
	else 
	  :
	fi
fi

if [ "$outfile" ]; then
	echo -e "\e[00;30m### SCAN COMPLETE ####################################\e[00m" >> $outfile
else
	echo -e "\e[00;30m### SCAN COMPLETE ####################################\e[00m"
fi
