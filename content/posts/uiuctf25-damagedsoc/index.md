---
title: UIUCTF 25 - Damaged SoC
date: 2025-08-10
lastmod: 2025-08-10T23:50:30+02:00
aliases: ["/posts/2025/08/uiuctf-2025-damaged-soc/"]
categories:
  - writeup
  - uiuctf25
tags:
  - reverse
  - hardware
  - ida
  - medium
authors:
  - Valenter
---
*Due to previous X ray damage, a part of SoC bFlash memory is corrupted. The board is unable to pass self-verification and boot. :/*

Looks like our SoC was hit by a cosmic ray that flipped a few bits, let's try to make sense of it and reverse the damage in order to get our board back up and running.

## Quick rundown

We're given a SystemVerilog-simulated IC that is (fortunately) already precompiled for us with Verilator; I won't go in depth into what SystemVerilog is and how it works in this writeup, but feel free to [dive deeper](https://www.systemverilog.io/) on your own, the gist of it is — it's a hardware description and verification language that uses the *synthesizable* subset to describe CPUs, memories, MMIO blocks and other components to model hardware, which can then be simulated by open or closed-source simulators like Verilator, Modelsim, etc.

The challenge hands us a metric ton of files:

```bash
├── infra
│   └── src
│       ├── modules
│       │   ├── adder.sv
│       │   ├── barrel_rotator32.sv
│       │   ├── barrel_shifter32.sv
│       │   ├── configurations.sv
│       │   ├── core_branch.sv
│       │   ├── core_forward.sv
│       │   ├── core_hazard.sv
│       │   ├── data_mem.sv
│       │   ├── mips_decoder.sv
│       │   ├── mips_define.sv
│       │   ├── mux.sv
│       │   ├── register.sv
│       │   └── structures.sv
│       ├── SOC.sv
│       └── units
│           ├── alu.sv
│           ├── au.sv
│           ├── core_EX.sv
│           ├── core_ID.sv
│           ├── core_IF.sv
│           ├── core_MEM.sv
│           ├── core.sv
│           ├── cp0.sv
│           ├── lu.sv
│           ├── regfile.sv
│           ├── stdout.sv
│           ├── timer.sv
│           └── VGA.sv
├── memory.mem
└── SOC_run_sim
```

but we don't need to go through all of them to understand what it does, in short:
- **infra/src** contains the register transfer level for the whole SoC, it's the high abstraction layer that describes how data is transformed as it is passed from register to register, it contains `SOC.sv`, which is the top level, `data_mem.sv`, which models the memory (more on this later), CPU pipeline stages, peripherals (UART/stdout, etc.) and all the support modules that together model the hardware the simulator runs.
- **memory.mem** is a text-hex file in `$readmemh` format (text, lines with `@ADDR` followed by hex bytes). Verilog allows you to initialize memory from a text file with either hex or binary values, in our case, `data_mem.sv` shows `$readmemh("memory.mem", data_seg);`
- **SOC_run_sim**, our executable, runs the simulation, loads a hex memory file (`memory.mem`) and starts up a MIPS64 little-endian CPU.


But let's cut to the chase, what is all of this actually doing?

```bash
$ ./SOC_run_sim
Bootloading
Starting verification:
Incorrect key
HALT
```

Well... not much right now.

Why is this happening? Well, the author mentioned that the memory is "corrupted", analyzing `memory.mem` we can see what's happening:

```hex
@00000000
28 09 00 00
00 00 00 00
ef bf bd ef
bf bd ef bf
...
```

The first few lines contain several `EF BF BD` (the UTF-8 replacement character, “�”), a clear sign of corruption.

Our goal is to recover the boot ROM from the corrupted image, decompile, understand the “key” check (as we will see, the flag itself), craft the correct string and **patch** the memory so the verification passes and the board “boots.”

## Decompiling

Like many modern reverse engineering challenges, this step won't be as easy as throwing the binary into IDA or Ghidra, it's a little trickier than that. Running `SOC_run_sim` through IDA awakens cosmic horrors that are best left undisturbed:

![idaSOC](/uiuctf2025/damaged-soc/screenshot-1.png)

Enter `sus.py`, courtesy of my teammate [@nect](https://theromanxpl0.it/members/nect/).

```python
f = open('memory.mem')

block={}

cur = -1
acc = b""

for l in f.readlines():
    if l.startswith('@'):
        if cur >= 0:
            block[cur] = acc

        acc = b""
        cur = int(l[1:], 16)
    else:
        for x in l.split():
            acc += int(x,16).to_bytes(1)

if cur >= 0:
    block[cur] = acc

o = open('out.bin', 'wb')

last_addr = 0
for addr, mem in sorted(block.items()):
    print("Addr:", addr)
    print(mem)

    o.write(b"\0"*(addr-last_addr))
    last_addr=addr+len(mem)
    o.write(mem)
```

It reads `memory.mem`, groups blocks by address (`@...`) and concatenates bytes, filling gaps with zeros, and writes everything to `out.bin`.

We can now repeat the previous step and decompile the newly obtained file with IDA,

- *File format: Binary file (raw).*
- *CPU: mipsl, ABI n64.*
- *Base address: `0x0`.*

![idamem](/uiuctf2025/damaged-soc/screenshot-2.png)

Much better.
The main code starts at `0x100`, it immediately prints:

- `"Bootloading\n"`
- `"Starting verification:"`

using a “UART print” routine (`sub_838`) that writes to MMIO `0x20000010`.

Running `strings` on `out.bin` lends us a few extra insights (and a little waste of time):

```bash
GCC: (GNU) 15.1.
xVB40
hB4x
<!CB4!
2B4&
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
Bootloading
Starting verification:
Incorrect key
HALT
===verification passed!===
vq{uv|qw
Incorrect key
```

**`vq{uv|qw`**
```
flag[15] = key[0]-16 = 'v'(118)-16 = 102 = 'f'
flag[16] = key[1]-16 = 'q'(113)-16 = 97 = 'a'
flag[17] = key[2]-16 = '{'(123)-16 = 107 = 'k'
flag[18] = key[3]-16 = 'u'(117)-16 = 101 = 'e'
flag[19] = key[4]-16 = 'v'(118)-16 = 102 = 'f'
flag[20] = key[5]-16 = '|'(124)-16 = 108 = 'l'
flag[21] = key[6]-16 = 'q'(113)-16 = 97 = 'a'
flag[22] = key[7]-16 = 'w'(119)-16 = 103 = 'g'`
```

...
Let's move on.

## Time to Rev

In `sub_100` the firmware sets the key pointer to the data blob starting at `unk_8`(memory offset `0x00000008` in `memory.mem`) and passes it to `sub_208` as `arg_18`, the pointer to the candidate flag buffer (which I'll call `buf` in the following examples)

```asm
dli   $v0, unk_8
sd    $v0, 0x70+var_58($sp)
```

The core of the flag verification lies in the function labelled `sub_208` by IDA, its prologue checks that `v0 == 0`, if it does, it jumps to the verification step `loc_224`, otherwise it makes a simulator syscall (`0x6D8`) and returns:

```vbnet
ROM:0000000000000208  nop
ROM:000000000000020C  lw     $v0, arg_0($sp) ; load first argument (stack slot IDA named arg_0)
ROM:0000000000000210  beqz   $v0, loc_224   ; if (v0 == 0) jump to verification
ROM:0000000000000214  nop                   ; branch-delay slot
ROM:0000000000000218  syscall 0x6D8        ; else: make a simulator syscall/trap
ROM:000000000000021C  jr     $ra            ; and return immediately
ROM:0000000000000220  nop
```
### 1. Prefix check: `uiuctf{` (bytes 0..6)

```asm
ld    $v0, arg_18($sp)   ; buf
lb    $v0, 0($v0)        ; buf[0]
xori  $v0, 0x75          ; 'u'
sltiu $v0, 1
andi  $v0, 0xFF
move  $v1, $v0

ld    $v0, arg_18($sp)
daddiu $v0, 1
lb    $v0, 0($v0)        ; buf[1]
xori  $v0, 0x69          ; 'i'
... (same pattern for 'u','c','t','f','{')
daddiu $v0, 6
lb    $v0, 0($v0)        ; buf[6]
xori  $v0, 0x7B          ; '{'
...
li    $v0, 7
bne   $v1, $v0, loc_318  ; require all 7 matches
```

in pseudoC:

```c
if ( (*a12 == 0x75LL)  // 'u'
    + (a12[1] == 0x69LL)  // 'i'
    + (a12[2] == 0x75LL)  // 'u'
    + (a12[3] == 0x63LL)  // 'c'
    + (a12[4] == 0x74LL)  // 't'
    + (a12[5] == 0x66LL)  // 'f'
    + (a12[6] == 0x7BLL) == 7LL )  // '{'
```

**`flag = uiuctf{`**
### 2. Mirror pattern for bytes 7 to 12

A loop runs with i = 0..5 (stored in `idx` at `0xC($sp)`), splitting into cases:

1) **i == 0 or 2** → `buf[i] == buf[i+7] + 0x20` (lowercase equals uppercase + 32) -> **`loc_410`** routine
2) **i == 1** → `buf[i+7] == '_'` -> **`loc_45C`** routine
3) **i == 3,4,5** → `buf[i] == buf[i+7]` -> **`loc_45C`**/**`loc_4A0`** routines

```asm
loc_3F4:
  lw    $v0, 0xC($sp)           ; idx
  beqz  $v0, loc_410            ; idx == 0 → case 1 (lowercase = uppercase+0x20)
  ...
  lw    $v1, 0xC($sp)
  li    $v0, 2
  bne   $v1, $v0, loc_45C       ; idx != 2 → cases 2/3
```

```asm
  ...
loc_410:                         ; case 1: idx==0 or idx==2
  lw    $v0, 0xC($sp)           ; idx
  ld    $v1, 0x18($sp)          ; buf
  daddu $v0, $v1, $v0
  lb    $v0, 0($v0)             ; a0 = buf[idx]
  move  $a0, $v0
  lw    $v0, 0xC($sp)
  daddiu $v0, 7
  ld    $v1, 0x18($sp)
  daddu $v0, $v1, $v0
  lb    $v0, 0($v0)             ; v0 = buf[idx+7]
  addiu $v0, 0x20               ; v0 += 0x20
  xor   $v0, $a0, $v0           ; buf[idx] == buf[idx+7] + 0x20
  sltiu $v0, 1
  andi  $v0, 0xFF
  ... accumulate into ok-bit ...
```

```asm
loc_45C:                         ; cases 2/3
  lw    $v1, 0xC($sp)
  li    $v0, 1
  bne   $v1, $v0, loc_4A0        ; if idx != 1 → case 3
  ...
  ; case B: idx == 1 → enforce underscore at buf[idx+7]
  lw    $v0, 0xC($sp)
  daddiu $v0, 7
  ld    $v1, 0x18($sp)
  daddu $v0, $v1, $v0
  lb    $v0, 0($v0)              ; buf[idx+7]
  xori  $v0, 0x5F                ; '_'
  sltiu $v0, 1
  ...
```

```asm
loc_4A0:                         ; case 3: idx in {3,4,5} → equality
  lw    $v0, 0xC($sp)
  ld    $v1, 0x18($sp)
  daddu $v0, $v1, $v0
  lb    $v1, 0($v0)              ; buf[idx]
  lw    $v0, 0xC($sp)
  daddiu $v0, 7
  ld    $a0, 0x18($sp)
  daddu $v0, $a0, $v0
  lb    $v0, 0($v0)              ; buf[idx+7]
  xor   $v0, $v1, $v0            ; buf[idx] == buf[idx+7]
  sltiu $v0, 1
  ...
```

in pseudoC:

```c
for (int i = 0; i < 6; i++) {
    if (i == 0 || i == 2) ok &= (buf[i] == (char)(buf[i+7] + 0x20));
    else if (i == 1)      ok &= (buf[i+7] == '_');
    else                  ok &= (buf[i] == buf[i+7]); // i in {3,4,5}
}
```

TL;DR: positions 7..12 mirror 0..5 as uppercase/same; position 8 is `_`

**`flag = uiuctf{U_Uctf`**

### 3. Stand-alone character checks

- `buf[13] == '_'`:

```asm
ld     $v0, 0x18($sp)
daddiu $v0, 0xD
lb     $v0, 0($v0)
xori   $v0, 0x5F          ; '_'
sltiu  $v0, 1
...
```

- `buf[14] == 'm'` and `buf[15] == '1'`:

```asm
ld     $v0, 0x18($sp)
daddiu $v0, 0xE
lb     $v1, 0($v0)
li     $v0, 0x6D          ; 'm'
bne    $v1, $v0, loc_630   ; fail if not 'm'
...
ld     $v0, 0x18($sp)
daddiu $v0, 0xF
lb     $v1, 0($v0)
li     $v0, 0x31          ; '1'
bne    $v1, $v0, loc_630
```

- `buf[28] == '_'`:

```asm
ld     $v0, 0x18($sp)
daddiu $v0, 0x1C
lb     $v1, 0($v0)
li     $v0, 0x5F          ; '_'
bne    $v1, $v0, loc_630
```

- `buf[23] + buf[24] == 'S'`

```asm
ld     $v0, 0x18($sp)
daddiu $v0, 0x17      ; buf[23]
lb     $v0, 0($v0)
move   $v1, $v0
ld     $v0, 0x18($sp)
daddiu $v0, 0x18      ; buf[24]
lb     $v0, 0($v0)
addu   $v0, $v1, $v0  ; sum
li     $v0, 0x53      ; 'S'
bne    $v1, $v0, loc_630
```

`'#' (0x23) + '0' (0x30) = 'S' (0x53)`

**`flag = uiuctf{U_Uctf_m1.......#0...._`**

### 4. Tail check: bytes 29..37 must be `abcdefghi`

Loop indexed by `arg_8`, 9 iterations:

```asm
loc_330:
  lw    $v0, arg_8($sp)
  addiu $v0, 0x1E        ; +30
  daddiu $v0, -1         ; +29
  ld    $v1, arg_18($sp)
  daddu $v0, $v1, $v0
  lb    $v1, 0($v0)      ; buf[29 + i]

  dli   $v0, 0
  lw    $a0, arg_8($sp)
  daddiu $v0, aAbcdefghijklmn  ; "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
  daddu $v0, $a0, $v0
  lb    $v0, 0($v0)      ; table[i]  → starts at 'a'
  xor   $v0, $v1, $v0    ; buf[29+i] == table[i]
  ...
  lw    $v0, arg_8($sp)
  addiu $v0, 1
  sw    $v0, arg_8($sp)

loc_390:
  lw    $v0, arg_8($sp)
  slti  $v0, 9           ; i < 9
  bnez  $v0, loc_330
```

in pseudoC:

```c
for ( i = 0; i < 9LL; ++i )
      v14 = (unsigned __int8)v14 & ((char)a12[i + 29] == (unsigned __int64)aAbcdefghijklmn[i]);
```

**`flag = uiuctf{U_Uctf_m1.......#0...._abcdefghi}`**

### 5. Central 8+4 byte mixing (bytes 16..23 and 24..27)

This is the trickiest part, this block derives two accumulators from 8 bytes at `[16..23]` and 4 bytes at `[24..27]`, mixes with constants, rotates, cross-mixes, and compares to targets:

**Load + constants + first XOR:**

```asm
ld    $v0, 0x18($sp)
ld    $v0, 0x10($v0)     ; packs buf[16..23] into 64b (little-endian)
sd    $v0, 0x20($sp)     ; save as x

ld    $v0, 0x18($sp)
lw    $v0, 0x18($v0)     ; packs buf[24..27] into 32b (little-endian)
sw    $v0, 0x28($sp)     ; save as y

dli   $v0, 0x1337C0DE12345678
sd    $v0, 0x30($sp)     ; c64
li    $v0, 0x3EADBE3F
sw    $v0, 0x38($sp)     ; c32

ld    $v1, 0x30($sp)     ; c64
ld    $v0, 0x20($sp)     ; x
xor   $v0, $v1, $v0
sd    $v0, 0x30($sp)     ; x ^= c64

lw    $v1, 0x38($sp)     ; c32
lw    $v0, 0x28($sp)     ; y
xor   $v0, $v1, $v0
sw    $v0, 0x38($sp)     ; y ^= c32
```

**Rotate-left and adds:**

```asm
; rol64(x,8) via shifts/ors then add 0x0123456789ABCDEF
...
dli   $v0, 0x123456789ABCDEF
daddu $v0, $v1, $v0    ; x += 0x0123456789ABCDEF
sd    $v0, 0x30($sp)

; rol32(y,4) then add 0x87654321
li    $v0, 0xFFFFFFFF87654321
addu  $v0, $v1, $v0    ; y += 0x87654321
sw    $v0, 0x38($sp)
```

**Cross-mix + final XORs + compare:**

```asm
; x ^= (uint64)y << 32
; y ^= (uint32)x
...
dli   $v0, 0xFEDCBA9876543210
xor   $v0, $v1, $v0     ; x ^= 0xFEDC...
sd    $v0, 0x30($sp)

li    $v0, 0x13579BDF
xor   $v0, $v1, $v0     ; y ^= 0x13579BDF
sw    $v0, 0x38($sp)

dli   $v0, 0xC956B3009784E40F
sd    $v0, 0x48($sp)
li    $v0, 0xFFFFFFFF83C5A9D1
sw    $v0, 0x50($sp)

ld    $v1, 0x30($sp)    ; x
ld    $v0, 0x48($sp)    ; target64
bne   $v1, $v0, loc_7D8 ; fail if x != target

lw    $v1, 0x38($sp)    ; y
lw    $v0, 0x50($sp)    ; target32
bne   $v1, $v0, loc_7D8 ; fail if y != target
```

in pseudoC:

```c
uint64_t x = u64le(&buf[16]) ^ 0x1337C0DE12345678ULL;
uint32_t y = u32le(&buf[24]) ^ 0x3EADBE3F;

x = rol64(x, 8) + 0x0123456789ABCDEFULL;
y = rol32(y, 4) + 0x87654321U;

x ^= ((uint64_t)y) << 32;
y ^= (uint32_t)x;

x ^= 0xFEDCBA9876543210ULL;
y ^= 0x13579BDFU;

ok &= (x == 0xC956B3009784E40FULL);
ok &= (y == 0x83C5A9D1U);
```

I used the following python script to demangle this part (with a bit of overlap with bytes already discovered in section 4):

```python
#decipher.py
def ror64(val, r):
    return ((val >> r) | (val << (64 - r))) & 0xFFFFFFFFFFFFFFFF

def ror32(val, r):
    return ((val >> r) | (val << (32 - r))) & 0xFFFFFFFF

def find_key_bytes():

    target_E = 0xC956B3009784E40F
    target_F = 0x83C5A9D1


    E = target_E ^ 0xFEDCBA9876543210
    F = target_F ^ 0x13579BDF
    print(f"After final inverse XOR: E=0x{E:016x}, F=0x{F:08x}")


    F_before_mix = F ^ (E & 0xFFFFFFFF)
    E_before_mix = E ^ (F_before_mix << 32)
    print(f"After inverse Feistel: E=0x{E_before_mix:016x}, F=0x{F_before_mix:08x}")


    E_before_add = (E_before_mix - 0x0123456789ABCDEF) & 0xFFFFFFFFFFFFFFFF
    F_before_add = (F_before_mix - 0x87654321) & 0xFFFFFFFF
    print(f"After subtraction: E=0x{E_before_add:016x}, F=0x{F_before_add:08x}")


    E_before_rot = ror64(E_before_add, 8)
    F_before_rot = ror32(F_before_add, 4)
    print(f"After inverse rotation: E=0x{E_before_rot:016x}, F=0x{F_before_rot:08x}")


    E_original = E_before_rot ^ 0x1337C0DE12345678
    F_original = F_before_rot ^ 0x3EADBE3F
    print(f"Original values: E=0x{E_original:016x}, F=0x{F_original:08x}")


    E_bytes = E_original.to_bytes(8, 'little')
    F_bytes = F_original.to_bytes(4, 'little')


    char23 = E_bytes[7]  #ultimo byte di E
    char24 = F_bytes[0]  #primo byte di F
    print(f"\nVerify sum: 0x{char23:02x} + 0x{char24:02x} = 0x{char23 + char24:02x} (Has to be 0x53)")


    print(f"\nBytes 16-23: {E_bytes.hex()} = '{E_bytes.decode('ascii', errors='replace')}'")
    print(f"Bytes 24-27: {F_bytes.hex()} = '{F_bytes.decode('ascii', errors='replace')}'")

    return E_bytes + F_bytes

result = find_key_bytes()
```

`Bytes 16-23: 70736c3076657223 = 'psl0ver#'`
`Bytes 24-27: 30643030 = '0d00'`

**`flag = uiuctf{U_Uctf_m1psl0ver#0d00_abcdefghi}`**

Now, if everything is correct, we should be able to patch our memory.mem file and see `\n===verification passed!===\n` printed in the output.

## Patching it up

Remember `data_mem.sv`?
In Verilog, the memory initialization function is defined as follows:

```
$readmemh("hex_memory_file.mem", memory_array, [start_address], [end_address])
```

`start_address` is optional and undefined in our case, so memory starts at 0x0.

The firmware reads the candidate key starting at absolute address 0x00000008 (`unk_8` in the disassembly), and in `memory.mem` the `@00000000` block clearly shows those `ef bf bd` bytes starting at offset `0x08`.

Now let's ASCII-encode the flag and add a null terminator at the end, while keeping the rest unchanged:

```
//memory.mem
@00000000
28 09 00 00
00 00 00 00
75 69 75 63
74 66 7b 55
5f 55 63 74
66 5f 6d 31
70 73 6c 30
76 65 72 23
30 64 30 30
5f 61 62 63
64 65 66 67
68 69 7d 00
47 43 43 3a
20 28 47 4e
```

*Make sure to keep the file name the same as well, the elf automatically takes `memory.mem` as input.*

![shell](/uiuctf2025/damaged-soc/screenshot-3.png)

Everything is back up and running!

Here is the final script I used during the CTF:

```python
from typing import Tuple

# do a barrel roll
def rol32(v: int, r: int) -> int:
    return ((v << r) & 0xFFFFFFFF) | (v >> (32 - r))

def ror32(v: int, r: int) -> int:
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF

def rol64(v: int, r: int) -> int:
    return ((v << r) & 0xFFFFFFFFFFFFFFFF) | (v >> (64 - r))

def ror64(v: int, r: int) -> int:
    return ((v >> r) | (v << (64 - r))) & 0xFFFFFFFFFFFFFFFF

# cryptoninja block
CT_X = 0xC956B3009784E40F
CT_Y = 0xFFFFFFFF83C5A9D1 & 0xFFFFFFFF       # 32 bit

def invert_block() -> Tuple[bytes, bytes]:

    x3 = CT_X ^ 0xFEDCBA9876543210
    y3 = (CT_Y ^ 0x13579BDF) & 0xFFFFFFFF     # 32 bit

    x3_low = x3 & 0xFFFFFFFF
    y2 = x3_low ^ y3
    x2 = x3 ^ (y2 << 32)

    x1 = (x2 - 0x0123456789ABCDEF) & 0xFFFFFFFFFFFFFFFF
    y1 = (y2 - 0xFFFFFFFF87654321) & 0xFFFFFFFF

    x0 = ror64(x1, 8)
    y0 = ror32(y1, 4)

    eight  = x0 ^ 0x1337C0DE12345678          # 64 bit
    four   = y0 ^ 0x3EADBE3F                  # 32 bit

    return eight.to_bytes(8, 'little'), four.to_bytes(4, 'little')

def build_flag() -> str:
    eight, four = invert_block()

    flag = (
        b"uiuctf{"          # prefix
        b"U_Uctf_"          # xor
        b"m1"               # dedicated check
        + eight             # bytes 16‑23
        + four              # bytes 24‑27
        + b"_"              # offset 28
        + b"abcdefghi"      # offset 29‑37
        + b"}"              # closure
    )
    return flag.decode()

#verifica
def verify(flag: str) -> bool:
    assert flag.startswith("uiuctf{") and flag.endswith("}")
    assert flag[7] == "U"
    assert flag[8] == "_"
    assert flag[9:13] == "Uctf"
    assert flag[13] == "_"
    assert flag[14:16] == "m1"
    assert (ord(flag[23]) + ord(flag[24])) == 0x53
    assert flag[28] == "_"
    assert flag[29:38] == "abcdefghi"
    import struct
    key = flag.encode()
    eight = int.from_bytes(key[16:24], 'little')
    four  = int.from_bytes(key[24:28], 'little')

    x = rol64((eight ^ 0x1337C0DE12345678), 8)
    x = (x + 0x0123456789ABCDEF) & 0xFFFFFFFFFFFFFFFF

    y = rol32((four ^ 0x3EADBE3F), 4)
    y = (y + 0xFFFFFFFF87654321) & 0xFFFFFFFF

    x ^= (y << 32)
    y ^= x & 0xFFFFFFFF
    x ^= 0xFEDCBA9876543210
    y ^= 0x13579BDF
    return x == CT_X and y == CT_Y

if __name__ == "__main__":
    flag = build_flag()
    print("Flag:", flag)
    assert verify(flag), "something went wrong!"
```


## Trivia and extras

**Fun fact:** the flag format was actually changed due to this solve during the course of the competition, after an exchange I had with one of the moderators; it initially did not contain a `#`, the full regex was `uiuctf{[a-zA-Z0-9_&]+}`, this made me double check and second guess the flag for quite a while before actually submitting it. No big deal though, it was fixed shortly after.

![discord_chat](/uiuctf2025/damaged-soc/screenshot-4.png)

During our first approach to the challenge, [@simonedimaria](https://theromanxpl0.it/members/simonedimaria/) managed to recompile the source files with debugging logs:

```
Interrupe Handler Address: 0000000008000040
---- Damaged region dump ----
mem[8] = ef
mem[9] = bf
mem[a] = bd
mem[b] = ef
mem[c] = bf
mem[d] = bd
mem[e] = ef
mem[f] = bf
mem[10] = bd
mem[11] = ef
mem[12] = bf
mem[13] = bd
mem[14] = ef
mem[15] = bf
mem[16] = bd
mem[17] = ef
mem[18] = bf
mem[19] = bd
mem[1a] = ef
mem[1b] = bf
mem[1c] = bd
mem[1d] = ef
mem[1e] = bf
mem[1f] = bd
mem[20] = ef
mem[21] = bf
mem[22] = bd
mem[23] = ef
mem[24] = bf
mem[25] = bd
mem[26] = ef
mem[27] = bf
mem[28] = bd
mem[29] = ef
mem[2a] = bf
mem[2b] = bd
mem[2c] = ef
mem[2d] = bf
mem[2e] = 7d
-----------------------------
PC=0x000000000000010c, inst=0x24190148, rs_data(t0)=0x0000000000000000, rt_data(i)=0x0000000000000000
writeback regnum = 29, data = 0000000000000d00
PC=0x0000000000000110, inst=0x03200009, rs_data(t0)=0x0000000000000000, rt_data(i)=0x0000000000000000
writeback regnum = 28, data = 0000000000000af0
PC=0x0000000000000114, inst=0x00000000, rs_data(t0)=0x0000000000000000, rt_data(i)=0x0000000000000000
writeback regnum = 31, data = 0000000000000d00
writeback regnum = 25, data = 0000000000000148
write addr: 0000000000000cf8, data: 0000000000000d00, type: 4
writeback regnum = 29, data = 0000000000000c90
writeback regnum =  2, data = 0000000000000000
...
```

Only to later realize that those were only `puts`-related logs, his contribution was nonetheless crucial to the final solution.
