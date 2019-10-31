---
layout: post
title: AceBear Security Contest - imageauth
categories: ctf_acebear18
keywords: "malware analysis"
comments: true
authors:
    - chq-matteo
---



## Challenge description

Authentication with password is sooooooo yesterday.

Challenge files: [Link](https://drive.google.com/open?id=1jn_dbPceBITjBePxVG4TVI2c7Lj-3jiO)

Authenticate at: [http://gudluck.h4ve.fun:8001/](http://gudluck.h4ve.fun:8001/)

## Solution

We can upload images to the server that with classify them with a neural network.

We have to submit an image that has a gud_prob > 0.99.

We are given the source code.

There is a lot of literature (research papers) about the subject of visualizing or even reversing a neural network, but I didn't find something easy to use.

Armed with ingenuity I decided to do it by hand.

Deploy the service locally and add a couple of debugging logs
- weights of various layers
- output values
- normalized image

At first I tried with some simple images like pure white and pure black, and get a gud_prob of around 0.5-0.6.

I noticed that in the normalized white image there were some different values for the different colour channels of the image.

I took note of the ratios and made an image filled with a colour that respected those ratios (dark grey) and got a gud_prob of 10 ^ -40 and every value in the normalized image was negative.

So I conjectured that the image had to be overall somewhat bright (mostly positive values).

I inverted the colour and got a score of 0.7.

I then tried to play with the scoring system one paint stroke at a time.

After each edit we submit and observe the change in the score, decide if we want to revert and the next edit.

## The final result

It doesn't work every time, but one time is enough.

<img class="img-responsive" src="{{ site-url }}/assets/acebear/black.png">
