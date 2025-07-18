---
title: CodeFest CTF 2017 - Lost in Translation Writeup
date: '2017-09-23'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- ctf_codefest17
- writeup
- codefest17
tags:
- steganography
authors:
- rop2bash
---

Listening to the file audio you can hear a clock.

Let's open it with Audacity and check if there's something.

<img class="img-responsive" src="{{ site-url }}/assets/codefest17/kappa.png" alt="Audio waveform in Audacity of audio file with clock sounds" width="603" height="132">

Apparently nothing.

But zooming in you can notice some irregualrities in the sound waves.

<img class="img-responsive" src="{{ site-url }}/assets/codefest17/kappa2.png" alt="Zoomed in view of audio waveform showing irregularities" width="603" height="48">

First thing I can think of is morse code

By decoding it we obtain the flag.

-> flag{h014_p33p5}
