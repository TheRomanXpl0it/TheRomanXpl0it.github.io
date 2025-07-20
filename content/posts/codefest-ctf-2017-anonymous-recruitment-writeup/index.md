---
title: CodeFest CTF 2017 - Anonymous Recruitment Writeup
date: '2017-09-24'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- writeup
- codefest17
tags:
- web
authors:
- dpstart
---

This is the page we see when we access the service:

<img class="img-responsive" src="/codefest17/cookie-1.png" alt="Signup form with username and password fields" width="603" height="258">

Going through the page cookies, I found this:

<img class="img-responsive" src="/codefest17/cookie-2.png" alt="Screenshot of cookie named 'flag' with true value" width="603" height="60">

I tried to set the *flag* cookie to *False* and send the form.
As a result, the old form is replaced by the following:

<img class="img-responsive" src="/codefest17/cookie-3.png" alt="Modified signup form with username as 'root'" width="603" height="476">

After several tries, I found out that the correct username was *root*.

I sent the form again:

<img class="img-responsive" src="/codefest17/cookie-6.png" alt="Submitted form with username as 'root'" width="603" height="465">


In the list of cookies, I now see this:

<img class="img-responsive" src="/codefest17/cookie-4.png" alt="Screenshot of 'pass' cookie containing MD5 hash" width="603" height="75">

The values of the *pass* cookie is an md5 hash for the word *aunty*.
I type it as a password, and I find out it's the flag:

<img class="img-responsive" src="/codefest17/cookie-5.png" alt="Page displaying flag after entering correct password" width="603" height="118">
