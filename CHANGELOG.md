# Changelog

Note: Export functionality is currently in the experimental stage.

## V0.982 (release 07-01-2020)
* Improvements to script execution speed by @Jrhenderson11 (https://github.com/rebootuser/LinEnum/pull/45 & https://github.com/rebootuser/LinEnum/commit/13741ce79fd5627da64bcf6a04fea11829e91ec8)

## V0.981 (release 21-11-2019)
* List permissions on PATH directories to see if they are writable by @stealthcopter
* Added checks for .bak files by @richardcurteis

## V0.98 (18-10-19 & 20-11-19)
* Added further useful binaries to list by @Anon-Exploiter
* Fixes to psql password issue by @Disassembler0

## V0.971 (11-09-19)
* Added useful binaries to list by @Anon-Exploiter

## V0.97 (release 09-07-2019)
* Improvements to TCP/UDP socket output by @Hypnoze57

## V0.96 (release 16-04-2019)
* Fixes to SUID/SGID checks

## V0.95 (release 24-01-2019)
Additions
* Additional checks provided by @djhohnstein (https://github.com/djhohnstein/LinEnum/commit/bf4ce1ad3beb392cab5d388e364972373533c721#diff-679e8fbdcfe07231f5eda7a8b491511dR1350)
* Searches /home for private key files
* Searches /home for AWS keys
* Searches / for git credential files 

Modifications
* SUID/SGID and capabilities checks moved from thorough to standard check
* False positive ssh-agent fix 
* Output text/small code changes and clean-up

## V0.9 (release 25-05-2018)
Additions
* Sudo/SUID/SGID binary list expanded to include entries from https://gtfobins.github.io/
* -s switch introduced. This allows you to supply the current user password for authenticated sudo 'checks'. Note; this is INSECURE and is really only for use in CTF environments

Modifications
* Sudo/suid/guid searches modified & bug in sudo parsing (when multiple entries are separated by commas) fixed
* Apache home dir output moved to thorough checks (due to extensive output)

## V0.8 (release 12-04-2018)
Additions
* Prints contents of users .bash_history (if found)
* Looks for users that have used sudo
* Checks for htpasswd files
* Lists hidden files
* Further checks/output in regards to viewing files the user owns
* Additional checks using newer ip commands
* Added PHP search for keywords

Modifications
* Code/commands cleaned
* Added [+] and [-] to output, to aid in searching through the generated report

## V0.7 (22-01-2018)
Additions
* LX Container checks
* Loaded Kernel Modules list
* adm group listing
* SELinux Presence

Modifications
* Code optimization: everything is in functions, cat grep awk pair optimized.

## V0.6 (release 12-05-2017)
Additions
* ARP information added
* Shows users currently logged onto the host
* Added checks to show env information
* Displays enabled Apache modules
* Checks to see if we're in a Docker container
* Checks to see if we're hosting Docker services

Modifications
* Tweaked the SSH search as we were getting false negatives
* Tweaked the searches used for SUID, GUID binaries
* Fixed issues with some commands not, or incorrectly, redirecting to error

## V0.5 (release 27-01-2014)
Additions
* Interface tweaks including the following additional switches:
** -e :export functionality
** -r :generate report output
** -t :perform thorough tests
* Thorough tests include lengthy checks, if the -t switch is absent, a default 'quick' scan is performed
* Export functionality copies 'interesting' files to a specified location for offline analysis
* Checks added for inetd.conf binary ownership
* Extracts password policy and hashing information from /etc/login.defs
* Checks umask value

Modifications
* Reporting functionality now has a dependency on 'tee'
* Fixed/modified user/group scan
* Tidied sudoer file extraction command

## V0.4 (release 05-08-2013)
Additions
* Added basic usage details to display on start-up
* Added cron.deny/cron.allow checks

Modifications
* Fixed printing of scan start date when output is saved to file
* Tidied up output when output is saved to a file

## V0.3 (release 30-08-2013)
Edited by Nikhil Sreekumar (@roo7break)
Enhancements
* Support for multiple keywords for searching added (space separated)
* Search for keywords optimised
* Store output to file and pass seach keywords from command line (e.g. ./LinEnum.sh output.txt "password credential username"

## V0.2 (release 30-08-2013)
Additions
* Date/time is displayed when the scan is started
* Checks for word-readable files in /home and displays positive matches
* Apache user config (user/group) details displayed (if applicable)
* Details all members of our users' current groups
* Lists available shells
* Performs basics SSH checks (i.e. what can be read/where is it stored and associated permissions)
* Locates and lists password hashes that may be found in /etc/passwd on old setups (big thanks to www.pentestmonkey.net)
* Locates credentials file and username/passwords in /etc/fstab

Modifications:
* ifconfig command simplified so 'br' & 'em' interfaces details are also shown
* Keyword search also includes *.ini files

## V0.1 (release 19-08-2013)
