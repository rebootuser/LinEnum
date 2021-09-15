#!/bin/env bash

#
#  linenum
#
# AUTHOR: @rebootuser et al.
#
# DESCRIPTION:
#    Linenum is a script designed to enumerate a linux box. It should work to varying
#    degrees on OSX/MacOS and various flavors of BSD.
#
# OUTPUT:
#    plain-text
#
# PLATFORMS:
#    Linux, OSX/MacOS, BSD
#
# DEPENDENCIES:
#    Bash
#
# USAGE:
#    See the help text for additional details
#   ./lineum
#
# NOTES:
#
# LICENSE:
#    MIT
#

version="version 0.982"
#@rebootuser

#help function
usage ()
{
echo -e "\n\e[00;31m#########################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com | @rebootuser \e[00m"
echo -e "\e[00;33m# $version\e[00m\n"
echo -e "\e[00;33m# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
		echo "-s 	Supply user password for sudo checks (INSECURE)"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name"
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"

echo -e "\e[00;31m#########################################################\e[00m"
}
header()
{
echo -e "\n\e[00;31m#########################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com\e[00m"
echo -e "\e[00;33m# $version\e[00m\n"

}

debug_info()
{
echo "[-] Debug Info"

if [ "$keyword" ]; then
	echo "[+] Searching for the keyword $keyword in conf, php, ini and log files"
fi

if [ "$report" ]; then
	echo "[+] Report name = $report"
fi

if [ "$export" ]; then
	echo "[+] Export location = $export"
fi

if [ "$thorough" ]; then
	echo "[+] Thorough tests = Enabled"
else
	echo -e "\e[00;33m[+] Thorough tests = Disabled\e[00m"
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
fi

if [ "$sudopass" ]; then
  echo -e "\e[00;35m[+] Please enter password - INSECURE - really only for CTF use!\e[00m"
  read -s userpassword
  echo
fi

who=`whoami` 2>/dev/null
echo -e "\n"

echo -e "\e[00;33mScan started at:"; date
echo -e "\e[00m\n"
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='aria2c\|arp\|ash\|awk\|base64\|bash\|busybox\|cat\|chmod\|chown\|cp\|csh\|curl\|cut\|dash\|date\|dd\|diff\|dmsetup\|docker\|ed\|emacs\|env\|expand\|expect\|file\|find\|flock\|fmt\|fold\|ftp\|gawk\|gdb\|gimp\|git\|grep\|head\|ht\|iftop\|ionice\|ip$\|irb\|jjs\|jq\|jrunscript\|ksh\|ld.so\|ldconfig\|less\|logsave\|lua\|make\|man\|mawk\|more\|mv\|mysql\|nano\|nawk\|nc\|netcat\|nice\|nl\|nmap\|node\|od\|openssl\|perl\|pg\|php\|pic\|pico\|python\|readelf\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-parts\|rvim\|scp\|script\|sed\|setarch\|sftp\|sh\|shuf\|socat\|sort\|sqlite3\|ssh$\|start-stop-daemon\|stdbuf\|strace\|systemctl\|tail\|tar\|taskset\|tclsh\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|wish\|xargs\|xxd\|zip\|zsh'





















footer()
{
echo -e "\e[00;33m### SCAN COMPLETE ####################################\e[00m"
}

call_each()
{
  header
  debug_info
  system_info
  user_info
  environmental_info
  job_info
  networking_info
  services_info
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  footer
}

while getopts "h:k:r:e:st" option; do
 case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    s) sudopass=1;;
    t) thorough=1;;
    h) usage; exit;;
    *) usage; exit;;
 esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
