#!/bin/bash

environmental_info()
{
echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m"

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31m[-] Environment information:\e[00m\n$envinfo"
  echo -e "\n"
fi

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "\e[00;31m[-] SELinux seems to be present:\e[00m\n$sestatus"
  echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls -ld $(echo $PATH | tr ":" " ")`
  echo -e "\e[00;31m[-] Path information:\e[00m\n$pathinfo"
  echo -e "$pathswriteable"
  echo -e "\n"
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31m[-] Available shells:\e[00m\n$shellinfo"
  echo -e "\n"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umaskvalue" ]; then
  echo -e "\e[00;31m[-] Current umask value:\e[00m\n$umaskvalue"
  echo -e "\n"
fi

#umask value as in /etc/login.defs
umaskdef=`grep -i "^UMASK" /etc/login.defs 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "\e[00;31m[-] umask value as specified in /etc/login.defs:\e[00m\n$umaskdef"
  echo -e "\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\e[00;31m[-] Password and storage information:\e[00m\n$logindefs"
  echo -e "\n"
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
fi
}
