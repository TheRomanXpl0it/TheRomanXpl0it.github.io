---
title: TAMUctf 18 - DESpicable me
date: '2018-03-01'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- tamuctf18
tags:
- reverse
- bruteforce
authors:
- dp_1
---

>Looks like Gru needs a new encryption scheme to facilitate his communication with the criminal council.
>
>Larry came up with a modified DES algorithm that he is pretty proud of...but this is Larry we are talking about.
>
>Make sure you can actually decrypt the message.
>
>Below is an encrypted communication between Gru and Larry used to test the algorithm. They used the following to encrypt the message.
>
>`larrycrypt -R 4 -K "V3c70R" -m message`
>
>Encrypted Bits: 000101 000000 100111 011001 101110 011101 001110 101111 010001 101111 110000 001001 110010 111011 110111 010001 000100 101011 100010 100010 000001 010100 001111 010010 111110 001110 000111
>
>Here is some relaxing music to soothe your frustration https://www.youtube.com/watch?v=9RHFFeQ2tu4

Being a reversing challenge, I first tried actually reversing it. Crypto algorithms are kind of boring when reversing though, especially unknown ones, so we moved on to other means to get to the flag. I made some assumptions that looked reasonable and made a bruteforce possible:
- that the encryption of each group of three input bytes was only dependent on previous bytes
- that after the first triplet that produces three output bytes all others would produce four
- that in each triplet other than the first the first character influenced the first output byte, the first and the second the second output byte, all three the full four byte output

Note that the solution is not necessarily unique when considering a prefix of the flag.

We had already obtained the first three bytes (`Gig`) with a bit of guessing, so with  these considerations in mind, I wrote (not without some effort, I had to change my assumptions a few times) a bruteforce that in less than 15 minutes got us the flag:

```python
import subprocess
import string
import random

alpha = [x for x in string.printable]
random.shuffle(alpha)

# Target string, without the first three octects which were bruteforced separately
target = '011001 101110 011101 001110 101111 010001 101111 110000 001001 110010 111011 110111 010001 000100 101011 100010 100010 000001 010100 001111 010010 111110 001110 000111'
target = target.split(' ')

def findThree(base):
	global target
	if len(target) < 4:
		#print "At least four output bytes are required"
		return []

	first = []
	for ch in alpha:
		if ch == '"' or ch == '`': continue
		out = subprocess.check_output('./larrycrypt -R 4 -K V3c70R -m "' + base + ch + 'aa"', shell=True).strip()
		if out.split(' ')[-4] == target[0]:
			first.append(ch)
	if len(first) == 0:
		return []
	# print "Possible first chars:", first
	target = target[1:]

	second = []
	for f in first:
		for ch in alpha:
			if ch == '"' or ch == '`': continue
			out = subprocess.check_output('./larrycrypt -R 4 -K V3c70R -m "' + base + f + ch + 'a"', shell=True).strip()
			if out.split(' ')[-3] == target[0]:
				second.append(f + ch)
	if len(second) == 0:
		return []
	# print "Possible two byte prefixes:", second
	target = target[1:]

	third = []
	for s in second:
		#print base + s
		for ch in alpha:
			if ch == '"' or ch == '`' or ch == '\\': continue
			out = subprocess.check_output('./larrycrypt -R 4 -K V3c70R -m "' + base + s + ch + '"', shell=True).strip()
			if out.split(' ')[-2] == target[0] and out.split(' ')[-1] == target[1]:
				third.append(base + s + ch)
	# print "Possible outputs:", third
	return third

start = ['Gig']
while len(target) > 0:
	out = []
	for e in start:
		t_target = target
		out += findThree(e)
		target = t_target

	start = out
	target = target[4:]
	print out

print [x for x in out if x[-1] == '}']
```

Which gave me `GigEm{I7's5ofLUFfy:)}"` as the flag.

```bash
dario@PC:~/desktop/ctf/tamu18/rev200$ time python t1.py
['GigEh%', 'GigEm{', 'GigFAD']
["GigEm{I7'"]
["GigEm{I7's5o", "GigEm{I7's5s", "GigEm{I7's5I", "GigEm{I7's5l"]
["GigEm{I7's5ofLU", "GigEm{I7's5ofLD", "GigEm{I7's5lqV>", "GigEm{I7's5lq_z", "GigEm{I7's5ls6;"]
["GigEm{I7's5ofLUFfy", "GigEm{I7's5ofLUFfp"]
["GigEm{I7's5ofLUFfy:)}", "GigEm{I7's5ofLUFfy:)p"]
["GigEm{I7's5ofLUFfy:)}"]

real    13m32.338s
user    1m35.500s
sys     11m26.359s
```
