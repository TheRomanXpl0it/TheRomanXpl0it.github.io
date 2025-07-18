---
title: BOH Challenges
date: '2019-04-07'
lastmod: '2019-04-07T14:29:47+02:00'
categories:
- articles
tags:
- pwn
authors:
- andreafioraldi
---

boh-lang is an intentionally vulnerable language.

Source [here](https://github.com/andreafioraldi/boh-lang).

I (malweisse) developed this shitty language to teach our new members about the art of
exploitation and now I'm going to release it with the same porpuse but for the
entire community this time.

Join the mini individual CTF [here](https://boh-chals.herokuapp.com/) to test your pwning ability.

This language has a compiler and a VM written in C++ (in less than 8k lines).
There are different challenges with different vulnerabilities, the hardest is the one related to the compiler optimizations (Trust my compiler).

There are two reasons behind this: teaching compiler theory (In our university a serious course is missing DOH!) and exploitation in a practical way.

Have fun and learn as much as possible!
