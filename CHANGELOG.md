# Changelog

Note: Export functionality is currently in the experimental stage.

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
