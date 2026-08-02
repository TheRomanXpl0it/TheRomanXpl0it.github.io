---
title: L3akCTF 2026 - Subleq Scramble
date: '2026-08-03T00:00:00+02:00'
math: false
categories:
- writeup
- l3akctf26
tags:
- reverse
- subleq
authors:
- ice cream
---

## Description

Some dude's been trying to hide even more secrets behind yet another one of his "all-new, totally one-of-a-kind encryption algorithms" that he'd been yapping about.

Apparently it's some sort of "subleq emulator" that runs thousands of iterations of an image encryption algorithm... before straight-up memdumping the entire program state into a binary file when it's done.

*All of it.*

Given that he was kind enough to send us an encrypted file, that probably means the algorithm's open-source now.

Nobody tell him.

Note: Flag format is /L3AK{[A-Z0-9?'_,]+}/


author Shatterbox

## Analysis

We can start by analyzing this challenge, we know from the name of the challenge and by the attachments that we are working with a [https://esolangs.org/wiki/Subleq](Subleq) program.

Subleq is a one instruction set architecture where the only instruction is `subleq a, b, c`, it does `memory[b] -= memory[a]` and if the result is less than or equal to zero, it jumps to `c`, otherwise it continues to the next instruction, there are also extensions like:
- `a == -1` it reads from stdin into `memory[b]`,
- `b == -1` it writes `memory[a]` to stdout
- `c == -1` it halts the program
in this case, it uses the standard Subleq where each memory cell is a 16-bit signed integer.

Now we can parse this "program" and see if there's anything useful:
```py
import struct

with open('data.subleq', 'rb') as f:
	data = f.read()

program = list(struct.unpack('<' + 'h' * (len(data) // 2), data))
print(program)
```

This results in:
```py
[0, 1, -1, 257, 260, 6, 252, 252, 9, 253, 253, 12, 261, 252, 15, 252, 253, 18, 252, 252, 21, 259, 252, 24, 1, 253, 30, 0, 0, 21, 258, 252, 33, 263, 252, 36, 90, 90, 39, 252, 90, 42, 136, 136, 45, 252, 136, 48, 97, 97, 51, 252, 97, 54, 252, 252, 57, 258, 252, 63, 0, 0, 168, 261, 253, 66, 253, 252, 168, 252, 252, 72, 253, 253, 75, 259, 252, 81, 0, 0, 168, 262, 253, 84, 253, 252, 168, 253, 253, 90, 3033, 253, 93, 2, 253, 135, 254, 3033, 99, 253, 253, 102, 252, 252, 105, 255, 252, 108, 252, 253, 111, 255, 255, 114, 253, 255, 117, 253, 253, 120, 252, 252, 123, 256, 252, 126, 252, 253, 129, 256, 256, 132, 253, 256, 135, 1, 3033, 138, 252, 252, 141, 256, 252, 144, 256, 256, 147, 255, 256, 150, 255, 255, 153, 252, 255, 156, 255, 258, 159, 256, 259, 162, 1, 260, 183, 0, 0, 6, 252, 252, 171, 195, 252, 183, 252, -1, 177, 2, 171, 180, 0, 0, 168, 258, -1, 186, 259, -1, 189, 260, -1, 192, 0, 0, -1, -65, -110, -116, -32, -111, -117, -116, -32, -111, -102, -32, -98, -111, -117, -110, -100, -115, -58, -10, -32, 0, -76, -51, -65, -75, -123, -105, -116, -45, -101, -110, -99, -114, -121, -112, -116, -115, -45, -105, -109, -97, -103, -101, -115, -45, -110, -111, -116, -45, -116, -101, -120, -116, -125, -10, -32, 0, -1, 0, -2, 1, 0, -9999, 80, 32, 0, 84, 38, 264, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

there is a strange sequence of numbers at the beginning, some of the chars seem to be ascii, maybe there are some strings there, so we can parse them as:
```py
print(bytes([abs(x) % 256 for x in program]))
```

that gives out 2 obvious strings: `Ant out of bounds:\n` and `L3AK{it-encrypts-images-not-text}\n`
so obviously I submitted it instantly:

![/l3akctf2026/subleq-scramble/fake_flag.png](/l3akctf2026/subleq-scramble/fake_flag.png)

so, given the CTF's ban policy, my reaction was:

![/l3akctf2026/subleq-scramble/ops.png](/l3akctf2026/subleq-scramble/ops.png)

I was like: NOOO PLZ DONT BAN ME, I'M NOT A CLANKER PLZZZZ

\* Nothing Happened \*

## The VM

Given that it wasn't the real flag, it's time to quickly implement this vm:
```py
import sys, struct


BITS = 16

class SubLeqVM:
	def __init__(self, program):
		self.mem = list(program)


	def run(self, debug_level=0):
		pc = 0
		while 0 <= pc < len(self.mem):
			a, b, c = self.mem[pc], self.mem[pc+1], self.mem[pc+2]
			# print(hex(a), hex(b), hex(c))

			if a == -1:
				self.mem[b] = sys.stdin.read(1).encode()[0]
				branch = True
			elif b == -1:
				sys.stdout.write(chr(self.mem[a] & 0xFF))
				sys.stdout.flush()
				branch = True

			else:
				self.mem[b] -= self.mem[a]
				if self.mem[b] >= (1 << (BITS-1)): self.mem[b] -= (1 << BITS) # handle overflow
				elif self.mem[b] < -(1 << (BITS-1)): self.mem[b] += (1 << BITS) # handle underflow

			branch = self.mem[b] <= 0

			if debug_level:
				print(
					f"pc={pc:04d} instr=({hex(a)},{hex(b)},{hex(c)}) "
					f"mem[{hex(a)}]={hex(self.mem[a])} mem[{hex(b)}]={hex(self.mem[b])} branch={branch} ",
					end=''
				)
				if debug_level < 2: print()
			if debug_level > 1: input()

			if branch:
				if c == -1:
					break
				pc = c
			else:
				pc += 3


		return self.mem


with open('data.subleq', 'rb') as f:
	data = f.read()

program = list(struct.unpack('<' + 'h' * (len(data) // 2), data))

vm = SubLeqVM(program)
vm.run(debug_level=0)

print()
```

This results in the following output:
```
Ant out of bounds:
 O&è
```
There we have the first string that we encountered.
Clearly, as a revver, I cannot accept to actually rev something, so I assumend that the program was doing some kind of Langton's Ant implementation.
Then I remembered that on the first output, where I found the 2 strings, there was a lot of 0s and 1s, so I tried to implement a simple function to render that as a bitmap:
```py
from PIL import Image

def save_bitmask(bitmask, pixel_size=1, output_file="frame.png"):
	height = len(bitmask)
	width = len(bitmask[0])

	img = Image.new("L", (width * pixel_size, height * pixel_size))

	for y, row in enumerate(bitmask):
		for x, bit in enumerate(row):
			color = 255 if bit else 0
			for dy in range(pixel_size):
				for dx in range(pixel_size):
					img.putpixel(
						(x * pixel_size + dx, y * pixel_size + dy),
						color
					)

	img.save(output_file)
	print(f"Saved image to {output_file}")
```

This worked, and I got:

![/l3akctf2026/subleq-scramble/frame_0.png](/l3akctf2026/subleq-scramble/frame_0.png)

I can see that there is the flag format there (`L3AK{`), so i tried to dump all the frames, and with some ffmpeg magic i got:
```bash
ffmpeg -framerate 30 -i frames/frame_%d.png -c:v libx264 -pix_fmt yuv420p output.mp4
```

![/l3akctf2026/subleq-scramble/output.gif](/l3akctf2026/subleq-scramble/output.gif)

## Solve

Now, to solve the challenge a Langton's Ant simulator might be useful, so I made the following using pygame:
```py
import pygame as pg
from collections import deque
import struct


class Ant:
	def __init__(self, app, pos, color, inv_color, direction=0):
		self.app = app
		self.color, self.inv_color = color, inv_color
		self.x, self.y = pos
		self.increments = deque([(1, 0), (0, 1), (-1, 0), (0, -1)])
		self.increments.rotate(direction) # 0=right, 1=down, 2=left, 3=up

	def run(self):
		value = self.app.grid[self.y][self.x]
		self.app.grid[self.y][self.x] = not value

		SIZE = self.app.CELL_SIZE
		rect = self.x * SIZE, self.y * SIZE, SIZE - 1, SIZE - 1
		if value: pg.draw.rect(self.app.screen, self.inv_color, rect)
		else:     pg.draw.rect(self.app.screen, self.color, rect)

		self.increments.rotate(1) if value else self.increments.rotate(-1)
		dx, dy = self.increments[0]
		self.x = (self.x + dx) % self.app.COLS
		self.y = (self.y + dy) % self.app.ROWS


class App:
	def __init__(self, grid, WIDTH=1280, HEIGHT=720, CELL_SIZE=8):
		pg.init()
		self.screen = pg.display.set_mode([WIDTH * CELL_SIZE, HEIGHT * CELL_SIZE])
		self.clock = pg.time.Clock()

		self.CELL_SIZE = CELL_SIZE
		self.ROWS, self.COLS = HEIGHT, WIDTH
		self.grid = grid
		for y, row in enumerate(grid):
			for x, bit in enumerate(row):
				color = pg.Color('white') if bit else pg.Color('black')
				rect = x * CELL_SIZE, y * CELL_SIZE, CELL_SIZE - 1, CELL_SIZE - 1
				pg.draw.rect(self.screen, color, rect)

		self.ants = [Ant(self, [START_X, START_Y], pg.Color('white'), pg.Color('black'), direction=START_DIRECTION)]


	def run(self):
		i = 0
		while True:
			[ant.inv_run() for ant in self.ants]

			[exit() for i in pg.event.get() if i.type == pg.QUIT]
			pg.display.flip()
			self.clock.tick(1000)

			i += 1
			if i >= 10000: input()
```

now the remaining part is to actually discover where the ant starts and in which direction, so by looking hard at the video I got the start as:
```py
START_X = 80
START_Y = 32
START_DIRECTION = 2 # 0=right, 1=down, 2=left, 3=up
```

A quick simulation, verified this start.

Now, to get the flag I just need to invert the simulation, so I implemented the `inv_run()` method for the `Ant` class as:
```py
def inv_run(self):
	dx, dy = self.increments[0]
	self.x = (self.x - dx) % self.app.COLS
	self.y = (self.y - dy) % self.app.ROWS

	value = self.app.grid[self.y][self.x]
	self.app.grid[self.y][self.x] = not value

	self.increments.rotate(1) if value else self.increments.rotate(-1)

	SIZE = self.app.CELL_SIZE
	rect = self.x * SIZE, self.y * SIZE, SIZE - 1, SIZE - 1
	if value: pg.draw.rect(self.app.screen, self.inv_color, rect)
	else:     pg.draw.rect(self.app.screen, self.color, rect)
```

Then just run the simulation:

![/l3akctf2026/subleq-scramble/solve.gif](/l3akctf2026/subleq-scramble/solve.gif)

### Flag

- `L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}`

## Final Scripts

### VM
```py
import sys, struct
from PIL import Image


WIDTH = 84
HEIGHT = 38


BITS = 16

class SubLeqVM:
	def __init__(self, program):
		self.mem = list(program)


	def run(self, debug_level=0):
		steps = 0
		pc = 0
		while 0 <= pc < len(self.mem):
			steps += 1
			bitmask = [self.mem[START+y*WIDTH:START+(y + 1)*WIDTH] for y in range(HEIGHT)]
			save_bitmask(bitmask, pixel_size=1, output_file=f"frames/frame_{steps}.png")

			a, b, c = self.mem[pc], self.mem[pc+1], self.mem[pc+2]
			# print(hex(a), hex(b), hex(c))

			if a == -1:
				self.mem[b] = sys.stdin.read(1).encode()[0]
				branch = True
			elif b == -1:
				sys.stdout.write(chr(self.mem[a] & 0xFF))
				sys.stdout.flush()
				branch = True

			else:
				self.mem[b] -= self.mem[a]
				if self.mem[b] >= (1 << (BITS-1)): self.mem[b] -= (1 << BITS) # handle overflow
				elif self.mem[b] < -(1 << (BITS-1)): self.mem[b] += (1 << BITS) # handle underflow

			branch = self.mem[b] <= 0

			if debug_level:
				print(
					f"pc={pc:04d} instr=({hex(a)},{hex(b)},{hex(c)}) "
					f"mem[{hex(a)}]={hex(self.mem[a])} mem[{hex(b)}]={hex(self.mem[b])} branch={branch} ",
					end=''
				)
				if debug_level < 2: print()
			if debug_level > 1: input()

			if branch:
				if c == -1:
					break
				pc = c
			else:
				pc += 3

		bitmask = [self.mem[START+y*WIDTH:START+(y + 1)*WIDTH] for y in range(HEIGHT)]
		save_bitmask(bitmask, pixel_size=1, output_file=f"frame_{steps}.png")

		return self.mem



def save_bitmask(bitmask, pixel_size=1, output_file="frame.png"):
	height = len(bitmask)
	width = len(bitmask[0])

	img = Image.new("L", (width * pixel_size, height * pixel_size))

	for y, row in enumerate(bitmask):
		for x, bit in enumerate(row):
			color = 255 if bit else 0
			for dy in range(pixel_size):
				for dx in range(pixel_size):
					img.putpixel(
						(x * pixel_size + dx, y * pixel_size + dy),
						color
					)

	img.save(output_file)
	print(f"Saved image to {output_file}")



with open('data.subleq', 'rb') as f:
	data = f.read()

program = list(struct.unpack('<' + 'h' * (len(data) // 2), data))
# print(program)

# print(bytes([abs(x) % 256 for x in program]))
# input()
#! L3AK{it-encrypts-images-not-text}   ???????????

START = len(program) - program[::-1].index(264)
print(len(program[START:]))
# bitmask = [program[START+y*WIDTH:START+(y + 1)*WIDTH] for y in range(HEIGHT)]
# save_bitmask(bitmask, pixel_size=32, output_file="frame.png")

vm = SubLeqVM(program)
vm.run(debug_level=0)

print()
```

### Ant Simulator
```py
import pygame as pg
from collections import deque
import struct


class Ant:
	def __init__(self, app, pos, color, inv_color, direction=0):
		self.app = app
		self.color, self.inv_color = color, inv_color
		self.x, self.y = pos
		self.increments = deque([(1, 0), (0, 1), (-1, 0), (0, -1)])
		self.increments.rotate(direction) # 0=right, 1=down, 2=left, 3=up

	def run(self):
		value = self.app.grid[self.y][self.x]
		self.app.grid[self.y][self.x] = not value

		SIZE = self.app.CELL_SIZE
		rect = self.x * SIZE, self.y * SIZE, SIZE - 1, SIZE - 1
		if value: pg.draw.rect(self.app.screen, self.inv_color, rect)
		else:     pg.draw.rect(self.app.screen, self.color, rect)

		self.increments.rotate(1) if value else self.increments.rotate(-1)
		dx, dy = self.increments[0]
		self.x = (self.x + dx) % self.app.COLS
		self.y = (self.y + dy) % self.app.ROWS


	def inv_run(self):
		dx, dy = self.increments[0]
		self.x = (self.x - dx) % self.app.COLS
		self.y = (self.y - dy) % self.app.ROWS

		value = self.app.grid[self.y][self.x]
		self.app.grid[self.y][self.x] = not value

		self.increments.rotate(1) if value else self.increments.rotate(-1)

		SIZE = self.app.CELL_SIZE
		rect = self.x * SIZE, self.y * SIZE, SIZE - 1, SIZE - 1
		if value: pg.draw.rect(self.app.screen, self.inv_color, rect)
		else:     pg.draw.rect(self.app.screen, self.color, rect)



class App:
	def __init__(self, grid, WIDTH=1280, HEIGHT=720, CELL_SIZE=8):
		pg.init()
		self.screen = pg.display.set_mode([WIDTH * CELL_SIZE, HEIGHT * CELL_SIZE])
		self.clock = pg.time.Clock()

		self.CELL_SIZE = CELL_SIZE
		self.ROWS, self.COLS = HEIGHT, WIDTH
		self.grid = grid
		for y, row in enumerate(grid):
			for x, bit in enumerate(row):
				color = pg.Color('white') if bit else pg.Color('black')
				rect = x * CELL_SIZE, y * CELL_SIZE, CELL_SIZE - 1, CELL_SIZE - 1
				pg.draw.rect(self.screen, color, rect)

		self.ants = [Ant(self, [START_X, START_Y], pg.Color('white'), pg.Color('black'), direction=START_DIRECTION)]


	def run(self):
		i = 0
		while True:
			[ant.inv_run() for ant in self.ants]

			[exit() for i in pg.event.get() if i.type == pg.QUIT]
			pg.display.flip()
			self.clock.tick(1000)

			i += 1
			if i == 1: input('Enter to start the simulation...')
			if i >= 10000: input('Enter to exit the simulation...')



with open('data.subleq', 'rb') as f:
	data = f.read()

program = list(struct.unpack('<' + 'h' * (len(data) // 2), data))
START = len(program) - program[::-1].index(264)
WIDTH = 84
HEIGHT = 38

START_X = 80
START_Y = 32
START_DIRECTION = 2 # 0=right, 1=down, 2=left, 3=up


grid = [program[START+y*WIDTH:START+(y + 1)*WIDTH] for y in range(HEIGHT)]

app = App(grid, WIDTH=WIDTH, HEIGHT=HEIGHT, CELL_SIZE=8)
app.run()


# L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}
```
