#!/bin/bash

# TODO: Create more descriptive function names

# Current User Details
current_user() {
  local curr_user
  curr_user=$(id 2>/dev/null)
  if [ "$curr_user" ]; then
    echo -e "\e[$cyan[-] Current user/group:\e[$default"
    echo -e "$curr_user\n"
  fi

  return 0
}

# Get a list of all logged in users
get_logged_in_users() {
  local logged_in_users
  logged_in_users=$(w 2>/dev/null)
  if [ "$logged_in_users" ]; then
    echo -e "\e[$cyan[-] Who else is logged on:\e[$default"
    echo -e "$logged_in_users\n"
  fi

  return 0
}

# Get info on users that have logged in previously
get_previous_logged_in_users() {
  local previous_users
  previous_users=$(lastlog 2>/dev/null | grep -v "Never" 2>/dev/null)
  if [ "$previous_users" ]; then
    echo -e "\e[$cyan[-] Users that have previously logged onto the system:\e[$default"
    echo -e "$previous_users\n"
  fi

  return 0
}

# Get a list of groups a user is in
get_user_groups() {
  local user
  local grp_info

  # shellcheck disable=SC2013
  grp_info=$(for user in $(cut -d":" -f1 /etc/passwd 2>/dev/null); do echo -e "$user : $(id "$user" | awk -F"groups=" '{ print $2 }' | column -t)"; done 2>/dev/null)
  if [ "$grp_info" ]; then
    echo -e "\e[$cyan[-] Group memberships:\e[$default"
    echo -e "$grp_info\n"
  fi

  return 0
}

# Checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
check_passwd_hashes() {
  local passwd_hashes
  passwd_hashes=$(grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null)
  if [ "$passwd_hashes" ]; then
    echo -e "\e[$cyan[-] It looks like we have password hashes in /etc/passwd!\e[$default\n$passwd_hashes"
    echo -e "\n"
  fi

  return 0
}

# Print the contents contents of /etc/passwd
# NOTE: Is this needed if we are using the other specialized functions
read_passwd_contents() {
  local passwd_contents
  # TODO: Make this a utility function
  while IFS= read -r line; do
    passwd_contents+=("$line")
  done </etc/passwd

  if [ "$passwd_contents" ]; then
    printf "%s[-] Contents of /etc/passwd:%s\n" "${cyan}" "${default}"
    printf "%s\n" "${passwd_contents[@]}"

    # BUG pass in the data, instead of recalling the function
    export_passwd_contents
  else
    printf "%s[-] Could not read /etc/passwd%s" "${purple}" "${default}"
  fi

  return 0
}

# TODO: Change $format to $location
# TODO: Change variable name from export as that is a std command
# If selected, export the contents of /etc/passwd
export_passwd_contents() {
  local contents
  # TODO: Make this a utility function
  contents=read_passwd_contents

  if [ "$export" ] && [ "$contents" ]; then
    printf "%s[-] Contents of /etc/passwd will be exported to  %s/etc-export/ %s\n" "${cyan}" "${format}" "${default}"
    # TODO: Check for errors when creating the directory
    mkdir "$format/etc-export/ 2>/dev/null"
    cp /etc/passwd "$format/etc-export/passwd 2>/dev/null"
  fi

  return 0

}

# Checks to see if the shadow file can be read
read_shadow_file_contents() {
  local shadow_file_contents
  # TODO: Make this a utility function
  while IFS= read -r line; do
    shadow_file_contents+=("$line")
  done </etc/shadow

  if [ "$shadow_file_contents" ]; then
    printf "%s[-] Contents of /etc/shadow:%s\n" "${cyan}" "${default}"
    printf "%s\n" "${shadow_file_contents[@]}"

    # BUG pass in the data, instead of recalling the function
    export_shadow_file
  else
    printf "%s[-] Could not read /etc/shadow%s" "${purple}" "${default}"
  fi

  return 0
}

# TODO: Change $format to $location
# TODO: Chnage variable name from export as that is a std command
# If selected, export the contents of /etc/shadow
export_shadow_file() {
  local contents
  # TODO: Make this a utility function
  contents=read_shadow_file_contents

  if [ "$export" ] && [ "$contents" ]; then
    printf "%s[-] Contents of /etc/shadow will be exported to  %s/etc-export/ %s\n" "${cyan}" "${format}" "${default}"
    # TODO: Check for errors when creating the directory
    mkdir "$format/etc-export/ 2>/dev/null"
    cp /etc/shadow $format/etc-export/shadow 2>/dev/null
  fi

  return 0
}

# Tries to read the BSD 'shadow' variant /etc/master.passwd
read_bsd_shadow_file() {
  bsd_shadow_file=/etc/master.passwd
  if test -f "$bsd_shadow_file"; then
    local shadow_file_contents
    # TODO: Make this a utility function
    while IFS= read -r line; do
      shadow_file_contents+=("$line")
    done </etc/master.passwd

    if [ "$shadow_file_contents" ]; then
      printf "%s[-] Contents of /etc/shadow:%s\n" "${cyan}" "${default}"
      printf "%s\n\n" "${shadow_file_contents[@]}"

      # BUG pass in the data, instead of recalling the function
      export_bsd_shadow_file
    else
      printf "%s[-] Could not read /etc/master.passwd%s\n\n" "${purple}" "${default}"
    fi
  else
    printf "%s[-] %s was not found %s\n\n" "${purple}" "${bsd_shadow_file}" "${default}"
  fi

  return 0
}

# TODO: Change $format to $location
# TODO: Chnage variable name from export as that is a std command
# If selected, export the contents of /etc/shadow
export_bsd_shadow_file() {
  local contents
  # TODO: Make this a utility function
  contents=read_bsd_bsd_shadow_file

  if [ "$export" ] && [ "$contents" ]; then
    printf "%s[-] Contents of /etc/master.passwd will be exported to  %s/etc-export/ %s\n\n" "${cyan}" "${format}" "${default}"
    # TODO: Check for errors when creating the directory
    mkdir "$format/etc-export/ 2>/dev/null"
    cp /etc/master.passwd "$format/etc-export/master.passwd 2>/dev/null"
  fi

  return 0
}

# Find accounts with uid 0
find_uid0_accounts() {
  # NOTE: Should this be a loop?
  local root_accounts
  root_accounts=$(grep -v -E "^#" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1}' 2>/dev/null)
  if [ "$root_accounts" ]; then
    printf "%s[-] Root accounts:%s\n\n" "${cyan}" "${default}"
    printf "%s\n" "${root_accounts}"
  else
    printf "%s[-] Could not read /etc/passwd%s\n\n" "${purple}" "${default}"
  fi

  return 0
}

#pull out vital sudoers info
print_sudoers_config() {
  local sudoers_config
  sudoers_config=$(grep -v -e '^$' /etc/sudoers 2>/dev/null | grep -v "#" 2>/dev/null)
  if [ "$sudoers_config" ]; then
    printf "%s[-] Sudoers configuration (condensed):%s\n\n" "${cyan}" "${default}"
    printf "%s\n" "${sudoers_config}"

    # BUG pass in the data, instead of recalling the function
    export_sudoers_config

  else
    printf "%s[-] Could not read /etc/sudoers%s\n\n" "${purple}" "${default}"
  fi

  return 0
}

# TODO: Change $format to $location
# TODO: Chnage variable name from export as that is a std command
# If selected, export the contents of /etc/shadow
export_sudoers_config() {
  local contents
  # TODO: Make this a utility function
  contents=read_bsd_bsd_shadow_file

  if [ "$export" ] && [ "$contents" ]; then
    printf "%s[-] Contents of /etc/sudoers will be exported to  %s/etc-export/ %s\n\n" "${cyan}" "${format}" "${default}"
    # TODO: Check for errors when creating the directory
    mkdir "$format/etc-export/ 2>/dev/null"
    cp /etc/sudoers "$format/etc-export/sudoers 2>/dev/null"
  fi

  return 0
}
user_info() {
  echo -e "\e[$orange###################### User/Group ##########################[$default" # TODO fix spacing

  # TODO: Change function names to be consistent

  current_user
  get_logged_in_users
  get_previous_logged_in_users
  get_user_groups
  check_passwd_hashes
  read_passwd_contents
  read_shadow_file_contents
  read_bsd_shadow_file
  find_uid0_accounts
  print_sudoers_config
  export_sudoers_config

  #added by phackt - look for adm group (thanks patrick)
  #  adm_users=$(echo -e "$grpinfo" | grep "(adm)")
  #  if [[ ! -z $adm_users ]]; then
  #    echo -e "\e[$cyan[-] It looks like we have some admin users:\e[$default\n$adm_users"
  #    echo -e "\n"
  #  fi

  #can we sudo without supplying a password
  sudoperms=$(echo '' | sudo -S -l -k 2>/dev/null)
  if [ "$sudoperms" ]; then
    echo -e "\e[$orange[+] We can sudo without supplying a password!\e[$default\n$sudoperms"
    echo -e "\n"
  fi

  #check sudo perms - authenticated
  if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudoauth=$(echo $user_password | sudo -S -l -k 2>/dev/null)
      if [ "$sudoauth" ]; then
        echo -e "\e[$orange[+] We can sudo when supplying a password!\e[$default\n$sudoauth"
        echo -e "\n"
      fi
    fi
  fi

  ##known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
  if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudopermscheck=$(echo $user_password | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null)
      if [ "$sudopermscheck" ]; then
        echo -e "\e[$orange[-] Possible sudo pwnage!\e[$default\n$sudopermscheck"
        echo -e "\n"
      fi
    fi
  fi

  #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
  sudopwnage=$(echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null)
  if [ "$sudopwnage" ]; then
    echo -e "\e[$orange[+] Possible sudo pwnage!\e[$default\n$sudopwnage"
    echo -e "\n"
  fi

  #who has sudoed in the past
  whohasbeensudo=$(find /home -name .sudo_as_admin_successful 2>/dev/null)
  if [ "$whohasbeensudo" ]; then
    echo -e "\e[$cyan[-] Accounts that have recently used sudo:\e[$default\n$whohasbeensudo"
    echo -e "\n"
  fi

  #checks to see if roots home directory is accessible
  rthmdir=$(ls -ahl /root/ 2>/dev/null)
  if [ "$rthmdir" ]; then
    echo -e "\e[$orange[+] We can read root's home directory!\e[$default\n$rthmdir"
    echo -e "\n"
  fi

  #displays /home directory permissions - check if any are lax
  homedirperms=$(ls -ahl /home/ 2>/dev/null)
  if [ "$homedirperms" ]; then
    echo -e "\e[$cyan[-] Are permissions on /home directories lax:\e[$default\n$homedirperms"
    echo -e "\n"
  fi

  #looks for files we can write to that don't belong to us
  if [ "$thorough" = "1" ]; then
    grfilesall=$(find / -writable ! -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null)
    if [ "$grfilesall" ]; then
      echo -e "\e[$cyan[-] Files not owned by user but writable by group:\e[$default\n$grfilesall"
      echo -e "\n"
    fi
  fi

  #looks for files that belong to us
  if [ "$thorough" = "1" ]; then
    ourfilesall=$(find / -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null)
    if [ "$ourfilesall" ]; then
      echo -e "\e[$cyan[-] Files owned by our user:\e[$default\n$ourfilesall"
      echo -e "\n"
    fi
  fi

  #looks for hidden files
  if [ "$thorough" = "1" ]; then
    hiddenfiles=$(find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null)
    if [ "$hiddenfiles" ]; then
      echo -e "\e[$cyan[-] Hidden files:\e[$default\n$hiddenfiles"
      echo -e "\n"
    fi
  fi

  #looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
  if [ "$thorough" = "1" ]; then
    wrfileshm=$(find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null)
    if [ "$wrfileshm" ]; then
      echo -e "\e[$cyan[-] World-readable files within /home:\e[$default\n$wrfileshm"
      echo -e "\n"
    fi
  fi

  if [ "$thorough" = "1" ]; then
    if [ "$export" ] && [ "$wrfileshm" ]; then
      mkdir $format/wr-files/ 2>/dev/null
      for i in $wrfileshm; do cp --parents $i $format/wr-files/; done 2>/dev/null
    fi
  fi

  #lists current user's home directory contents
  if [ "$thorough" = "1" ]; then
    homedircontents=$(ls -ahl ~ 2>/dev/null)
    if [ "$homedircontents" ]; then
      echo -e "\e[$cyan[-] Home directory contents:\e[$default\n$homedircontents"
      echo -e "\n"
    fi
  fi

  #checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
  if [ "$thorough" = "1" ]; then
    sshfiles=$(find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \; 2>/dev/null)
    if [ "$sshfiles" ]; then
      echo -e "\e[$cyan[-] SSH keys/host information found in the following locations:\e[$default\n$sshfiles"
      echo -e "\n"
    fi
  fi

  if [ "$thorough" = "1" ]; then
    if [ "$export" ] && [ "$sshfiles" ]; then
      mkdir $format/ssh-files/ 2>/dev/null
      for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
    fi
  fi

  #is root permitted to login via ssh
  sshrootlogin=$(grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}')
  if [ "$sshrootlogin" = "yes" ]; then
    echo -e "\e[$cyan[-] Root is allowed to login via SSH:\e[$default"
    grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
    echo -e "\n"
  fi
}
