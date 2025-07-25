---
title: backdoorctf 2017 - dead-png2 Writeup
date: '2017-09-25'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- backdoorctf17
tags:
- forensics
- data-recovery
authors:
- dp_1
---

We're given a file that we're told is a corrupted png file. Having a first look at it in a hex editor, I couldn't find any of the normal headers that are normally present in a png file, so I added them back in.
I didn't know much about the png file format, but a quick google search cleared up the missing details for me.

The file is composed of a small header and a number of sections, each having a standard format:

<table class="table">
    <thead>
        <tr>
            <th>Offset</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>0</td>
            <td>Section size</td>
        </tr>
        <tr>
            <td>4</td>
            <td>Section name</td>
        </tr>
        <tr>
            <td>8</td>
            <td>Section data</td>
        </tr>
        <tr>
            <td>datalen+12</td>
            <td>CRC32 of name+data</td>
        </tr>
    </tbody>
</table>

What I did is add the header and the mandatory sections, namely IHDR, IDAT and IEND. Since the IDAT section contains the image data I also made sure that the size and CRC32 matched its contents.

All that was left to do was to mess around with the contents of the IHDR section in order to find the right color type, color depth and size of the image. For the color type I uncompressed the original data - it's zlib - and found out it was in RGBA format, also known as color type 6.
The size took a bit or trial and error, but in the end I had a complete png file from which I could read the flag.

Thinking of it now, I could have probably saved a bit of time by importing the raw rgba data in some software, but still, it worked this way and didn't take long anyways.
