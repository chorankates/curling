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


## flag
```
user:
root:
```
