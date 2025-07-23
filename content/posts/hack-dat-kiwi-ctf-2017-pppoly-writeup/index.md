---
title: Hack Dat Kiwi CTF 2017 - Pppoly Writeup
date: '2017-10-16'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- hackdatkiwi17
tags:
- reverse
- php
authors:
- dp_1
---

This was a nice reversing challenge, starting with a php file:


```php
<?php
$password='KIWIMASTER';
$d='3c3f7068700a24703d275a47566d49484e725... [rest of hex data removed for clarity]';
eval(substr(pack("H*",$d),5));

```

The obvious first thing to do was changing that `eval` for an `echo` in order to get this:

```php
<?php
$p='ZGVmIHNrZXdlcih0KToK... [rest of base64 data removed]';
$p=str_replace("pb24", base64_encode($password), base64_decode($p));
function into_temp($code)
{
    $f=tempnam(null,"polyglot_");
    file_put_contents($f, $code);
    return $f;
}
function sys($code,$pl)
{
    return shell_exec($pl." ".into_temp($code));
}
if (strpos($r=sys($p,"python"),"YES")!==false and ctype_alnum($password)) $r.=md5($password);
echo $r;
```
What it does is base64 decode the data contained in `$p`, put the password in place of the `pb24` placeholder and execute it as python, collecting its output. If the output contains "YES" then the md5 of the password is calculated, which will become the flag. Let's have a look at the python code, shall we?

```python
def skewer(t):
    return ord(t)-53;

import sys,base64,os,re;

password=base64.b64decode("pb24");
r=[chr((x+5+y**2)%256) for y,x in enumerate([skewer(x)+7%256 for x in password])];

code='''
#code here
use MIME::Base64;
my $pwd=decode_base64("JASUS");
$pwd=substr($pwd,-3).substr($pwd,0,(length $pwd) -3);
#print $pwd;
use File::Temp qw(tempfile);
($fh, $filename) = tempfile( );
my $code="<".<<'Y';
?php $p='JERKY';echo $flag=$p[0]=='A'?$p[1]=='S'?$p[2]=='S'?$p[3]=='H'?$p[4]=='A'?$p[5]=='I'?$p[6]=='R'?strlen($p)==7?'YES, the flag is: ':0:0:0:0:0:0:0:'NO';
Y
$code =~ s/JERKY/$pwd/g; print $fh $code;print `php ${filename}`;
'''.replace('JASUS',base64.b64encode("".join(r)));

import tempfile;
f = tempfile.NamedTemporaryFile(delete=False);
f.write(code);
f.close();
print os.popen("perl "+f.name).read();

```

What we get is another layer of indirection, this time using a perl script and collecting its output. There is also some password mangling going on in the first lines, but nothing we can't easily reverse later. The perl script uses a similar scheme as the other layers, calling a small php snippet that checks the password. Here it is formatted a little better:

```php
<?php

$p='JERKY';
echo $flag =
    $p[0]=='A'?
        $p[1]=='S'?
            $p[2]=='S'?
                $p[3]=='H'?
                    $p[4]=='A'?
                        $p[5]=='I'?
                            $p[6]=='R'?
                                strlen($p)==7?
                                    'YES, the flag is: '
                                :0
                            :0
                        :0
                    :0
                :0
            :0
        :0
    :'NO';
```

Where "JERKY" is as usual a placeholder for the password. From the checks we can easily see that the password has to be a very polite "ASSHAIR" in order for this code to print the success message. It still doesn't print the flag, so that's what we're going to focus on next.

The first obstacle we meet is the following perl line, which simply rotates the string, meaning the password now has to be "HAIRASS" for the checks to work as we want them to:
```perl
$pwd=substr($pwd,-3).substr($pwd,0,(length $pwd) -3);
```

Then we get back to the python layer, with a slightly more complicated mangling function:
```python
def skewer(t):
    return ord(t)-53;

r=[chr((x+5+y**2)%256) for y,x in enumerate([skewer(x)+7%256 for x in password])];
```
Here r must contain `['H','A','I','R','A','S','S']` after the mangling has occurred. We could either run this through an automated solved or reverse the function by hand. I chose the latter and wrote the following to do so:
```python
print "".join([chr(ord(ch) - i**2 + 41) for i,ch in enumerate("HAIRASS")])
```
Which quickly gave me back `qinrZcX` as the password to put into the original file in order to get the flag. As an afterthought, I could have just calculated its md5 instead of running the php, but I was sure it wouldn't harm my computer and it was just as easy to do.
