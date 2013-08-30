# Changelog

## V0.1 (release 19-08-2013)

## V0.2 (release 30-08/2013)
Additions
* Date/time is displayed when the scan is started
* Checks for word-readable files in /home and displays positive matches
* Apache user config (user/group) details displayed (if applicable)
* Details all members of our users' current groups
* Lists available shells
* Performs basics SSH checks (i.e. what can be read/where is it stored and associated permissions)
* Locates and lists password hashes that may be found in /etc/passwd on old setups (big thanks to www.pentestmonkey.net)

Modifications:
* ifconfig command simplified so 'br' & 'em' interfaces details are also shown
* Keyword search also includes *.ini files
