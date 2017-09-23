## CodeFest CTF 17 - Yemen Writeup

Another PNG this time with a black and white squares pattern.

Again a contrast and brightness trick.

![yemen_img](images/dots.png)

This time we encounter a strange pattern.
If we think of the pure black parts as 0 and the black and white ones as 1 we get some binary code for each line.

Bin | Hex | ASCII
-- | -- | --
01010100 | 0x54 | T
01001000 | 0x48 | H
01000101 | 0x45 | E
01000011 | 0x43 | C
01001111 | 0x4f | O
01000100 | 0x44 | D
01000101 | 0x45 | E
01010010 | 0x52 | R

and it repeats itself.

-> flag{THECODER}
