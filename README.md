# LinEnum
For more information visit www.rebootuser.com

For silent (and clean output) Outfile and keyword(s) can be supplied from the command line:
usage ./LinEnum.sh outfile.txt 'keyword1 keyword2'

Thanks to @roo7break for the above reporting functionality

See CHANGELOG.md for further details

High-level summary of the checks/tasks performed by LinEnum:

* Kernel and distribution release details
* System Information:
 * Hostname
 * Networking details:
 * Current IP
 * Default route details
 * DNS server information
* User Information:
 * Current user details
 * Last logged on users
 * List all users including uid/gid information
 * List root accounts
 * Checks if password hashes are stored in /etc/passwd
 * Extract full details for ‘default’ uid’s such as 0, 1000, 1001 etc
 * Attempt to read restricted files i.e. /etc/shadow
 * List current users history files (i.e .bash_history, .nano_history etc.)
 * Basic SSH checks
* Privileged access:
 * Determine if /etc/sudoers is accessible
 * Determine if the current user has Sudo access without a password
 * Are known ‘good’ breakout binaries available via Sudo (i.e. nmap, vim etc.)
 * Is root’s home directory accessible
 * List permissions for /home/
* Environmental:
 * Display current $PATH
* Jobs/Tasks:
 * List all cron jobs
 * Locate all world-writable cron jobs
 * Locate cron jobs owned by other users of the system
* Services:
 * List network connections (TCP & UDP)
 * List running processes
 * Lookup and list process binaries and associated permissions
 * List inetd.conf/xined.conf contents and associated binary file permissions
 * List init.d binary permissions
* Version Information (of the following):
 * Sudo
 * MYSQL
 * Postgres
 * Apache
  * Checks user config
* Default/Weak Credentials:
 * Checks for default/weak Postgres accounts
 * Checks for default/weak MYSQL accounts
* Searches:
 * Locate all SUID/GUID files
 * Locate all world-writable SUID/GUID files
 * Locate all SUID/GUID files owned by root
 * Locate ‘interesting’ SUID/GUID files (i.e. nmap, vim etc)
 * List all world-writable files
 * Find/list all accessible *.plan files and display contents
 * Find/list all accesible *.rhosts files and display contents
 * Show NFS server details
 * Locate *.conf and *.log files containing keyword supplied at script runtime
 * List all *.conf files located in /etc
 * Locate mail