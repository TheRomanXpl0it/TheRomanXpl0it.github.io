---
layout: post
title: EvlzCTF - Primeates
categories: ctf_evlzctf18
keywords: "crypto"
comments: true
authors:
    - daniele-cappuccio
---


After playing with nc for a little while, we discovered that the decryption algorithm simply extracts the cube root of the number (the encrypted data). Due to the big number we are dealing with, you have two different ways to solve this challenge: either use [Sage](http://www.sagemath.org/),
or just use WolframAlpha to compute all the roots. And yes, my laziness made me use the second way :)
