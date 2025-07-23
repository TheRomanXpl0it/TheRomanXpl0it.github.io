---
title: Hack Dat Kiwi CTF 2017 - Eluware1 Writeup
date: '2017-10-16'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- hackdatkiwi17
tags:
- forensics
authors:
- dp_1
---

The Eluware 1 challenge was quite simple. A copy of a website was displayed with a malicious `www.malware.com/md5.js` script added to it.
The script contained a `flag()` function, which when called from the Js console returned the flag to be submitted.
Probably the easiest 100 points I ever got in a challenge.
