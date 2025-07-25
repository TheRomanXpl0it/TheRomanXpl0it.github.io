---
title: backdoorctf 2017 - ecb Writeup
date: '2017-09-24'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- writeup
- backdoorctf17
tags:
- forensics
- steganography
authors:
- rop2bash
---

We know that images encypted with an ECB algorithm leave some traces or pattern of the original image [ex.](https://i.stack.imgur.com/bXAUL.png).

img1

<img class="img-responsive" src="/backdoorctf17/ecb-1.png" alt="Original encrypted image 1" width="603" height="354.7">

img2

<img class="img-responsive" src="/backdoorctf17/ecb-2.png" alt="Original encrypted image 2" width="603" height="354.7">

Well those don't resemble ECB encrypted images, but we are pure hearted and innocent so we decide to believe in the challenge name and description and start playing around with the images in GIMP and Stegosolve.

After some time we start seeing something:

img1


<img class="img-responsive" src="/backdoorctf17/ecb-3.png" alt="Image 1 with purple patterns highlighting possible characters" width="603" height="354.7">


<img class="img-responsive" src="/backdoorctf17/ecb-4.png" alt="Image 1 with black patterns highlighting possible characters" width="603" height="354.7">

img2


<img class="img-responsive" src="/backdoorctf17/ecb-5.jpg" alt="Image 2 with different purple patterns highlighting possible characters" width="603" height="354.7">


<img class="img-responsive" src="/backdoorctf17/ecb-6.png" alt="Image 2 with black patterns highlighting possible characters" width="603" height="354.7">

By overlapping the images and tracing over the lines we can more or less read the flag.

<img class="img-responsive" src="/backdoorctf17/ecb-7.png" alt="Overlayed and edited image revealing handwritten flag" width="603" height="355">
