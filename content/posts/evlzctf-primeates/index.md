---
title: EvlzCTF - Primeates
date: '2018-02-13'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- ctf_evlzctf18
- writeup
- evlzctf18
tags:
- crypto
authors:
- daniele-cappuccio
---

After playing with nc for a little while, we discovered that the decryption algorithm simply extracts the cube root of the number (the encrypted data). Due to the big number we are dealing with, you have two different ways to solve this challenge: either use [Sage](http://www.sagemath.org/),
or just use WolframAlpha to compute all the roots. And yes, my laziness made me use the second way :)
