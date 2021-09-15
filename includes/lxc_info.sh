#!/bin/bash

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null`
if [ "$lxccontainer" ]; then
  echo -e "\e[00;33m[+] Looks like we're in a lxc container:\e[00m\n$lxccontainer"
  echo -e "\n"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep -i lxd 2>/dev/null`
if [ "$lxdgroup" ]; then
  echo -e "\e[00;33m[+] We're a member of the (lxd) group - could possibly misuse these rights!\e[00m\n$lxdgroup"
  echo -e "\n"
fi
}
