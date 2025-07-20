---
title: CodeFest CTF 2017 - The Eights Writeup
date: '2017-09-23'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- writeup
- codefest17
tags:
- forensics
- steganography
authors:
- rop2bash
---

Another PNG this time with a black and white squares pattern.

Again a contrast and brightness trick.

<img class="img-responsive" src="/codefest17/dots.png" alt="Modified black and white image revealing ASCII characters" width="603" height="357">

This time we encounter a strange pattern.
If we think of the pure black parts as 0 and the black and white ones as 1 we get some binary code for each line.

<table class="table">
    <thead>
        <tr>
            <th>Bin</th>
            <th>Hex</th>
            <th>ASCII</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>01010100</td>
            <td>0x54</td>
            <td>T</td>
        </tr>
        <tr>
            <td>01001000</td>
            <td>0x48</td>
            <td>H</td>
        </tr>
        <tr>
            <td>01000101</td>
            <td>0x45</td>
            <td>E</td>
        </tr>
        <tr>
            <td>01000011</td>
            <td>0x43</td>
            <td>C</td>
        </tr>
        <tr>
            <td>01001111</td>
            <td>0x4f</td>
            <td>O</td>
        </tr>
        <tr>
            <td>01000100</td>
            <td>0x44</td>
            <td>D</td>
        </tr>
        <tr>
            <td>01000101</td>
            <td>0x45</td>
            <td>E</td>
        </tr>
        <tr>
            <td>01010010</td>
            <td>0x52</td>
            <td>R</td>
        </tr>
    </tbody>
</table>

and it repeats itself.

-> `flag{THECODER}`
