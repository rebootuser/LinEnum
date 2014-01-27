#!/bin/bash
#A simple script to enumerate local information from a Linux host
#version 0.2
#@oshearing

echo -e "\n\e[00;30m#########################################################\e[00m"
echo -e "\e[00;34mLocal Linux Enumeration & Privilege Escalation Script\e[00m"
echo -e "\e[00;30m#########################################################\e[00m"
echo -e "\e[00;30m# www.rebootuser.com\e[00m"
echo -e "\e[00;30m# version 0.2\e[00m\n"

#enter a single keyword that'll be used to search within *.conf, *.log & *.ini files.
echo "Enter a keyword that'll be used to search in *.conf, *.log and *.ini files (i.e. password)"
read keyword

who=`whoami`

echo -e "\n"
echo -e "\e[00;30mScan started at:"; date
echo -e "\e[00m\n"

echo -e "\e[00;34m### SYSTEM ##############################################\e[00m"

unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31mKernel information:\e[00m\n$unameinfo"
  echo -e "\n"
else 
  :
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31mKernel information (continued):\e[00m\n$procver"
  echo -e "\n"
else 
  :
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31mSpecific release information:\e[00m\n$release"
  echo -e "\n"
else 
  :
fi

hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31mHostname:\e[00m\n$hostnamed"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### USER/GROUP ##########################################\e[00m"

currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31mCurrent user/group info:\e[00m\n$currusr"
  echo -e "\n"
else 
  :
fi

grpinfo=`getent group $who 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31mAll members of 'our' group(s):\e[00m\n$grpinfo"
  echo -e "\n"
else 
  :
fi

lastlogedonusrs=`lastlog |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m\n$lastlogedonusrs"
  echo -e "\n"
else 
  :
fi

usrsinfo=`cat /etc/passwd | cut -d ":" -f 1,2,3,4 2>/dev/null`
if [ "$usrsinfo" ]; then
  echo -e "\e[00;31mAll users and uid/gid info:\e[00m\n$usrsinfo"
  echo -e "\n"
else 
  :
fi

hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33mIt looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd"
  echo -e "\n"
else 
  :
fi
 
#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd"
  echo -e "\n"
else 
  :
fi

readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow"
  echo -e "\n"
else 
  :
fi

readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd"
  echo -e "\n"
else 
  :
fi

#all root accounts (uid 0)
echo -e "\e[00;31mSuper user account(s):\e[00m"; grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'
echo -e "\n"

#pull out vital sudoers info
sudoers=`cat /etc/sudoers 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31mSudoers configuration:\e[00m"; cat /etc/sudoers 2>/dev/null | grep -A 1 "User priv"; cat /etc/sudoers | grep -A 1 "Allow"
  echo -e "\n"
else 
  :
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33mWe can sudo without supplying a password!\e[00m\n$sudoperms"
  echo -e "\n"
else 
  :
fi

#known 'good' breakout binaries
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage"
  echo -e "\n"
else 
  :
fi

rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir"
  echo -e "\n"
else 
  :
fi

homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms"
  echo -e "\n"
else 
  :
fi

wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
if [ "$wrfileshm" ]; then
  echo -e "\e[00;31mWorld-readable files within /home:\e[00m\n$wrfileshm"
  echo -e "\n"
else 
  :
fi

homedircontents=`ls -ahl ~ 2>/dev/null`
if [ "$homedircontents" ]; then
  echo -e "\e[00;31mHome directory contents:\e[00m\n$homedircontents"
  echo -e "\n"
else 
  :
fi

sshfiles=`find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la`
if [ "$sshfiles" ]; then
  echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles"
  echo -e "\n"
else 
  :
fi

sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m"; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### ENVIRONMENTAL #######################################\e[00m"

pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  echo -e "\e[00;31mPath information:\e[00m\n$pathinfo"
  echo -e "\n"
else 
  :
fi

shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31mAvailable shells:\e[00m\n$shellinfo"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### JOBS/TASKS ##########################################\e[00m"

cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31mCron jobs:\e[00m\n$cronjobs"
  echo -e "\n"
else 
  :
fi

cronjobwwperms=`find /etc/cron* -perm -0002 -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m***World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms"
  echo -e "\n"
else 
  :
fi

crontab=`cat /etc/crontab 2>/dev/null`
if [ "$crontab" ]; then
  echo -e "\e[00;31mCrontab contents:\e[00m\n$crontab"
  echo -e "\n"
else 
  :
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31mAnything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar"
  echo -e "\n"
else 
  :
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31mAnacron jobs and associated file permissions:\e[00m\n$anacronjobs"
  echo -e "\n"
else 
  :
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31mWhen were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab"
  echo -e "\n"
else 
  :
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31mJobs held by all users:\e[00m\n$cronother"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### NETWORKING  ##########################################\e[00m"

nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;31mNetwork & IP info:\e[00m\n$nicinfo"
  echo -e "\n"
else 
  :
fi

nsinfo=`cat /etc/resolv.conf 2>/dev/null | grep "nameserver"`
if [ "$nsinfo" ]; then
  echo -e "\e[00;31mNameserver(s):\e[00m\n$nsinfo"
  echo -e "\n"
else 
  :
fi

defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;31mDefault route:\e[00m\n$defroute"
  echo -e "\n"
else 
  :
fi

tcpservs=`netstat -antp 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;31mListening TCP:\e[00m\n$tcpservs"
  echo -e "\n"
else 
  :
fi

udpservs=`netstat -anup 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;31mListening UDP:\e[00m\n$udpservs"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### SERVICES #############################################\e[00m"

psaux=`ps aux 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "\e[00;31mRunning processes:\e[00m\n$psaux"
  echo -e "\n"
else 
  :
fi

#lookup process binary path and permissisons
procperm=`ps aux | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++'`
if [ "$procperm" ]; then
  echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m\n$procperm"
  echo -e "\n"
else 
  :
fi

inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "\e[00;31mContents of /etc/inetd.conf:\e[00m\n$inetdread"
  echo -e "\n"
else 
  :
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`cat /etc/inetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31mThe related inetd binary permissions:\e[00m\n$inetdbinperms" 
  echo -e "\n"
else 
  :
fi


xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "\e[00;31mContents of /etc/xinetd.conf:\e[00m\n$xinetdread"
  echo -e "\n"
else 
  :
fi

xinetdincd=`cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null
  echo -e "\n"
else 
  :
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`cat /etc/xinetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31mThe related xinetd binary permissions:\e[00m\n$xinetdbinperms"; 
  echo -e "\n"
else 
  :
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "\e[00;31m/etc/init.d/ binary permissions:\e[00m\n$initdread"
  echo -e "\n"
else 
  :
fi  

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  echo -e "\e[00;31m/etc/rc.d/init.d binary permissions:\e[00m\n$rcdread"
  echo -e "\n"
else 
  :
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "\e[00;31m/usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### SOFTWARE #############################################\e[00m"

sudover=`sudo -V | grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "\e[00;31mSudo version:\e[00m\n$sudover"
  echo -e "\n"
else 
  :
fi

mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver"
  echo -e "\n"
else 
  :
fi

mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m***We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect"
  echo -e "\n"
else 
  :
fi

mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "\e[00;33m***We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass"
  echo -e "\n"
else 
  :
fi

postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31mPostgres version:\e[00m\n$postgver"
  echo -e "\n"
else 
  :
fi

postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1"
  echo -e "\n"
else 
  :
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11"
  echo -e "\n"
else 
  :
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2"
  echo -e "\n"
else 
  :
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22"
  echo -e "\n"
else 
  :
fi

apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "\e[00;31mApache version:\e[00m\n$apachever"
  echo -e "\n"
else 
  :
fi

apacheusr=`cat /etc/apache2/envvars 2>/dev/null |grep -i 'user\|group' |awk '{sub(/.*\export /,"")}1'`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31mApache user configuration:\e[00m\n$apacheusr"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;34m### INTERESTING FILES ####################################\e[00m"
echo -e "\e[00;31mUseful file locations:\e[00m"      ;which nc 2>/dev/null; which netcat 2>/dev/null; which wget 2>/dev/null; which nmap 2>/dev/null; which gcc 2>/dev/null
echo -e "\n"
echo -e "\e[00;31mCan we read/write sensitive files:\e[00m"	;ls -la /etc/passwd 2>/dev/null; ls -la /etc/group 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null
echo -e "\n"

findsuid=`find / -perm -4000 -type f 2>/dev/null`
if [ "$findsuid" ]; then
  echo -e "\e[00;31mSUID files:\e[00m\n$findsuid"
  echo -e "\n"
else 
  :
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la`
if [ "$intsuid" ]; then
  echo -e "\e[00;33m***Possibly interesting SUID files:\e[00m\n$intsuid"
  echo -e "\n"
else 
  :
fi

wwsuid=`find / -perm -4007 -type f 2>/dev/null`
if [ "$wwsuid" ]; then
  echo -e "\e[00;31mWorld-writable SUID files:\e[00m\n$wwsuid"
  echo -e "\n"
else 
  :
fi

wwsuidrt=`find / -uid 0 -perm -4007 -type f 2>/dev/null`
if [ "$wwsuidrt" ]; then
  echo -e "\e[00;31mWorld-writable SUID files owned by root:\e[00m\n$wwsuidrt"
  echo -e "\n"
else 
  :
fi

findguid=`find / -perm -2000 -type f 2>/dev/null`
if [ "$findguid" ]; then
  echo -e "\e[00;31mGUID files:\e[00m\n$findguid"
  echo -e "\n"
else 
  :
fi

#list of 'interesting' guid files - feel free to make additions
intguid=`find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la`
if [ "$intguid" ]; then
  echo -e "\e[00;33m***Possibly interesting GUID files:\e[00m\n$intguid"
  echo -e "\n"
else 
  :
fi

wwguid=`find / -perm -2007 -type f 2>/dev/null`
if [ "$wwguid" ]; then
  echo -e "\e[00;31mWorld-writable GUID files:\e[00m\n$wwguid"
  echo -e "\n"
else 
  :
fi

wwguidrt=`find / -uid 0 -perm -2007 -type f 2>/dev/null`
if [ "$wwguidrt" ]; then
  echo -e "\e[00;31mAWorld-writable GUID files owned by root:\e[00m\n$wwguidrt"
  echo -e "\n"
else 
  :
fi

#list all world-writable files excluding /proc
wwfiles=`find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null`
if [ "$wwfiles" ]; then
  echo -e "\e[00;31mWorld-writable files (excluding /proc):\e[00m\n$wwfiles"
  echo -e "\n"
else 
  :
fi

usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$usrplan"
  echo -e "\n"
else 
  :
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$bsdusrplan"
  echo -e "\n"
else 
  :
fi

rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$rhostsusr"
  echo -e "\n"
else 
  :
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$bsdrhostsusr"
  echo -e "\n"
else 
  :
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  echo -e "\e[00;31mHosts.equiv file details and file contents: \e[00m\n$rhostssys"
  echo -e "\n"
  else 
  :
fi

nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "\e[00;31mNFS config details: \e[00m\n$nfsexports"
  echo -e "\n"
  else 
  :
fi

fstab=`cat /etc/fstab 2>/dev/null |grep username |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1'| xargs -r echo username:; cat /etc/fstab 2>/dev/null |grep password |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1'| xargs -r echo password:; cat /etc/fstab 2>/dev/null |grep domain |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1'| xargs -r echo domain:`
if [ "$fstab" ]; then
  echo -e "\e[00;33m***Looks like there are credentials in /etc/fstab!\e[00m\n$fstab"
  echo -e "\n"
  else 
  :
fi

fstabcred=`cat /etc/fstab 2>/dev/null |grep cred |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1'| xargs -I{} sh -c 'ls -la {}; cat {}'`
if [ "$fstabcred" ]; then
    echo -e "\e[00;33m***/etc/fstab contains a credentials file!\e[00m\n$fstabcred"
    echo -e "\n"
    else
    :
fi

#use supplied keyword and cat *.conf files for potentional matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "Can't search *.conf files as no keyword was entered\n"
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey"
      echo -e "\n"
     else 
	echo -e "\e[00;31mFind keyword ($keyword) in .conf files (recursive 4 levels):\e[00m"
	echo -e "'$keyword' not found in any .conf files"
	echo -e "\n"
    fi
fi

#use supplied keyword and cat *.log files for potentional matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "Can't search *.log files as no keyword was entered\n"
  else
    logkey=`find / -maxdepth 2 -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .log files (recursive 2 levels - output format filepath:identified line number where keyword appears):\e[00m\n$logkey"
      echo -e "\n"
     else 
	echo -e "\e[00;31mFind keyword ($keyword) in .log files (recursive 2 levels):\e[00m"
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n"
    fi
fi

#use supplied keyword and cat *.ini files for potentional matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "Can't search *.ini files as no keyword was entered\n"
  else
    logkey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$logkey"
      echo -e "\n"
     else 
	echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 2 levels):\e[00m"
	echo -e "'$keyword' not found in any .ini files"
	echo -e "\n"
    fi
fi

allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  echo -e "\e[00;31mAll *.conf files in /etc (recursive 1 level):\e[00m\n$allconf" 
  echo -e "\n"
else 
  :
fi

usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  echo -e "\e[00;31mCurrent user's history files:\e[00m\n$usrhist" 
  echo -e "\n"
else 
  :
fi

roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "\e[00;33m***Root's history files are accessible!\e[00m\n$roothist"
  echo -e "\n"
else 
  :
fi

readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "\e[00;31mAny interesting mail in /var/mail:\e[00m\n$readmail"
  echo -e "\n"
else 
  :
fi

readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;30m### SCAN COMPLETE ####################################\e[00m"

