---
title: UIUCTF 25 - ELF Capsule
date: '2025-07-29T11:15:30+02:00'
math: false
categories:
- writeup
- uiuctf25
tags:
- reverse
- riscv
authors:
- Elius
- ice cream
- Massi2
---

## Description

The ELF cannot be effectively delivered without the ELF.

Note: The flag consists of only printable ASCII characters.

The flag has format uiuctf{...}, and inputs to program should follow this format.
Your solve script shouldn't take more than 10 minutes to run.

Author: CBCicada

## Analysis

First thing first, we can start by throwing common commands against this binary, such as `strings` or `binwalk`, `binwalk` finds a hidden binary inside the binary, this will be useful later; in the strings there is not something useful.

In the main RICV binary, following a bit of the code flow from the `start` function, we see that we arrive through `sub_80000060` at `loc_80000E78` which loads the addr of the inner elf into a register and then it calls `sub_800004BC` that will dispatch the embedded binary

```c
loc_80000E78:
    addi    sp, sp, -20h
    sd      ra, 18h(sp)
    sd      s0, 10h(sp)
    addi    s0, sp, 20h # ' '
    call    sub_80000210
    addi    a1, s0, -18h
    la      a0, unk_80001000 # Inner Binary
    call    sub_800004BC # Dispatch function
    lui     a0, 801h
    ld      a1, -18h(s0)
    slli    a0, a0, 8
    la      a2, unk_80006010
    addi    a0, a0, -1
    call    sub_800001DC
```

We will return to this binary after looking the second one.

### Inner binary

As there's only one function present, it’s time to dig into it. Immediately, three patterns stand out, each mimicking virtual machine instructions implemented via exception-driven control flow.

In RISCV, invalid memory accesses raise exceptions that provide context through two special registers:
- `scause`: indicates the type of fault (e.g., **5** for load access fault, **7** for store/AMO access fault)
- `stval`: holds the offending address, which in our case is crafted to act as an opcode

The handler in the main binary (at `sub_800001C0`) uses these values to determine what action to take. Specifically:

This transforms `stval` into an indexable opcode.
Thus, load and store instructions to invalid addresses are used intentionally to encode calls to virtual instructions. There are three key patterns:


**Pattern 1**: Store to an invalid address — triggers `scause = 7`
```c
li   a5, 421h
la   a4, aWhatIsTheFlag # "What is the flag?"
sd   a4, 0(a5)
```
This triggers the VM handler, which reads `stval = 0x421` and `scause = 7`, resulting in a store-based opcode lookup.


**Pattern 2**: Load from an invalid address — triggers `scause = 5`
```c
li  a5, 0DD3h
ld  a5, 0(a5)
```
Now the VM handler sees `stval = 0xDD3` and `scause = 5`, and dispatches the corresponding "load" opcode.


**Pattern 3**: Computed addresses and mixed instructions
```c
lui   a5, 1
addi  a4, a5, -37Ah
li    a5, 0DD3h
ld    a4, 0(a4)
sd    a4, 0(a5)
```
In this case, address values are calculated dynamically before being used in a `ld` or `sd`, resulting again in a VM "call" through exception handling. The store and load exceptions are used interchangeably depending on which virtual instruction is being simulated.

This exception-based dispatch mechanism lets the embedded binary implement a full virtual instruction set without needing a real dispatcher loop, relying instead on the RISC-V architecture’s exception handling features to interpret VM opcodes.


## Main binary

As we saw earlier `sub_800001C0` contains the code of the functions that are called with codes as invalid memory addresses, there are two branches, one for operation type (load and store), that will do 2 similar operations, for example the xor operation is defined as `stack[-1] ^= a4` for the stores and `a4 = stack[-2] ^ stack[-1]` for the loads, this pattern is shared between all operations + some functions that are one, the inverse of the other (like `push` and `pop`).

## Decompiler

Given the previous patterns is possible to write a simple pattern matching decompiler (more like a function call resolver) for the inner binary.

We can start by enumerating all the found functions from the first binary function `sub_800001C0` which contains all the "opcodes" that are called, and also we notice that the "load and "store" operations are actually two different type of instructions. (the `push_call` are like the init of a for loop and we have 3 of them, then the `pop_call` is the dec of the loop index)

```py
sd_codes = {
	0: 'exit',
    105: 'print a4',
    719: 'push_call_1',
    720: 'push_call_2',
    721: 'push_call_3',
    1195: 'push a4',
    1401: 'stack[-1] |= a4',
    1763: 'stack[-1] ^= a4',
    3094: 'stack[-1] *= a4',
    3291: 'stack[-1] rol= a4',
    3625: 'encrypt a4',
    3893: 'stack[-1] += a4'
}

ld_codes = {
	0: 'exit',
    105: 'getchar a4',
    719: 'pop_call_1',
    720: 'pop_call_2',
    721: 'pop_call_3',
    1195: 'pop a4',
    1401: 'a4 = stack[-2] | stack[-1]',
    1763: 'a4 = stack[-2] ^ stack[-1]',
    3094: 'a4 = stack[-2] * stack[-1]',
    3291: 'a4 = rol stack[-2] stack[-1]',
    3625: 'decrypt a4',
    3893: 'a4 = stack[-2] + stack[-1]'
}

def decode_vm_opcode(stval):
    return (105 * (stval ^ 0x420)) & 0xFFF
```

then we can extract the values that will be called

```py
li_regex = re.compile(r"li\s*a(.),\s(.*)h")

if m := li_regex.match(inst):
	if int(m.group(1)) == 4:
		if a4 is not None:
			print(f"Warn: Found 'li a4' double at {hex(addr)}")
			break
		a4 = int(m.group(2), 16)
	else:
		if a5 is not None:
			print(f"Warn: Found 'li a5' double at {hex(addr)}")
			break
		a5 = int(m.group(2), 16)
	addr += inst_size
	continue
```

we can now resolve the "store" calls into a real call

```py
sd_regex = re.compile(r"s(d|b)\s*(a4|zero),\s0\(a(.)\)")

if m := sd_regex.match(inst):
	if int(m.group(3)) == 4:
		if a4 is None:
			print(f"Warn: Found 'sd a4' without a4 at {hex(addr)}")
			break
		real_func = decode_vm_opcode(a4)
		real_func = sd_codes.get(real_func, f'unknown_{real_func}')
		a4 = None
	else:
		if a5 is None:
			print(f"Warn: Found 'sd a5' without a5 at {hex(addr)}")
			break
		real_func = decode_vm_opcode(a5)
		real_func = sd_codes.get(real_func, f'unknown_{real_func}')
		a5 = None
	inst = f'{real_func}'
```

then we step to the "load" calls that are similar to the above

```py
ld_regex = re.compile(r"l(d|bu)\s*a.,\s0\(a(.)\)")

if m := ld_regex.match(inst):
	if int(m.group(2)) == 4:
		if a4 is None:
			print(f"Warn: Found 'ld a4' without a4 at {hex(addr)}")
			break
		real_func = decode_vm_opcode(a4)
		real_func = ld_codes.get(real_func, f'unknown_{real_func}')
		a4 = None
	else:
		if a5 is None:
			print(f"Warn: Found 'ld a5' without a5 at {hex(addr)}")
			break
		real_func = decode_vm_opcode(a5)
		real_func = ld_codes.get(real_func, f'unknown_{real_func}')
		a5 = None
	inst = f'{real_func}'
```

then we can end with the "lui" calls

```py
lui = 'lui             a5, 1'
addi_regex = re.compile(r"addi\s*a.,\sa.,\s(.*)h")

if lui in inst:
	addi_inst = idc.GetDisasm(addr+inst_size)
	addi_insn = ida_ua.insn_t()
	ida_ua.decode_insn(addi_insn, addr+inst_size)
	inst_size += addi_insn.size

	m = addi_regex.match(addi_inst)
	a4 = int(m.group(1), 16)

	addr += inst_size
	continue
```

### Final Code

```py
import ida_hexrays
import ida_lines
import ida_funcs
import ida_kernwin
import idautils
import idc
import idaapi
import ida_ua

import re


ea = idaapi.get_screen_ea()
func = ida_funcs.get_func(ea)

if not func:
	print("No function found at the current address.")
	exit(1)

start = func.start_ea
end = func.end_ea

sd_codes = {
	0: 'exit',
    105: 'print a4',
    719: 'push_call_1',
    720: 'push_call_2',
    721: 'push_call_3',
    1195: 'push a4',
    1401: 'stack[-1] |= a4',
    1763: 'stack[-1] ^= a4',
    3094: 'stack[-1] *= a4',
    3291: 'stack[-1] rol= a4',
    3625: 'encrypt a4',
    3893: 'stack[-1] += a4'
}

ld_codes = {
	0: 'exit',
    105: 'getchar a4',
    719: 'pop_call_1',
    720: 'pop_call_2',
    721: 'pop_call_3',
    1195: 'pop a4',
    1401: 'a4 = stack[-2] | stack[-1]',
    1763: 'a4 = stack[-2] ^ stack[-1]',
    3094: 'a4 = stack[-2] * stack[-1]',
    3291: 'a4 = rol stack[-2] stack[-1]',
    3625: 'decrypt a4',
    3893: 'a4 = stack[-2] + stack[-1]'
}

def decode_vm_opcode(stval):
    return (105 * (stval ^ 0x420)) & 0xFFF


li_regex = re.compile(r"li\s*a(.),\s(.*)h")
sd_regex = re.compile(r"s(d|b)\s*(a4|zero),\s0\(a(.)\)")
ld_regex = re.compile(r"l(d|bu)\s*a.,\s0\(a(.)\)")
lui = 'lui             a5, 1'
addi_regex = re.compile(r"addi\s*a.,\sa.,\s(.*)h")

PRINT = 1

insts = []
a4 = None
a5 = None

addr = start
while addr < end:
	inst = idc.GetDisasm(addr)
	insn = ida_ua.insn_t()
	ida_ua.decode_insn(insn, addr)
	inst_size = insn.size

	if m := li_regex.match(inst):
		if int(m.group(1)) == 4:
			if a4 is not None:
				print(f"Warn: Found 'li a4' double at {hex(addr)}")
				break
			a4 = int(m.group(2), 16)
		else:
			if a5 is not None:
				print(f"Warn: Found 'li a5' double at {hex(addr)}")
				break
			a5 = int(m.group(2), 16)
		addr += inst_size
		continue

	elif m := sd_regex.match(inst):
		if int(m.group(3)) == 4:
			if a4 is None:
				print(f"Warn: Found 'sd a4' without a4 at {hex(addr)}")
				break
			real_func = decode_vm_opcode(a4)
			real_func = sd_codes.get(real_func, f'unknown_{real_func}')
			a4 = None
		else:
			if a5 is None:
				print(f"Warn: Found 'sd a5' without a5 at {hex(addr)}")
				break
			real_func = decode_vm_opcode(a5)
			real_func = sd_codes.get(real_func, f'unknown_{real_func}')
			a5 = None
		inst = f'{real_func}'

	elif m := ld_regex.match(inst):
		if int(m.group(2)) == 4:
			if a4 is None:
				print(f"Warn: Found 'ld a4' without a4 at {hex(addr)}")
				break
			real_func = decode_vm_opcode(a4)
			real_func = ld_codes.get(real_func, f'unknown_{real_func}')
			a4 = None
		else:
			if a5 is None:
				print(f"Warn: Found 'ld a5' without a5 at {hex(addr)}")
				break
			real_func = decode_vm_opcode(a5)
			real_func = ld_codes.get(real_func, f'unknown_{real_func}')
			a5 = None
		inst = f'{real_func}'

	elif lui in inst:
		addi_inst = idc.GetDisasm(addr+inst_size)
		addi_insn = ida_ua.insn_t()
		ida_ua.decode_insn(addi_insn, addr+inst_size)
		inst_size += addi_insn.size

		m = addi_regex.match(addi_inst)
		a4 = int(m.group(1), 16)

		addr += inst_size
		continue



	insts.append((addr, inst))
	if PRINT:
		print(f"{hex(addr)}: {inst}")

	addr += inst_size

else:
	with open('decomp.txt', 'w') as f:
		for addr, inst in insts:
			f.write(f"loc_{hex(addr)[2:]}: {inst}\n")
			if inst.startswith('j') or inst.startswith('exit') or inst.startswith('b'):
				f.write("\n\n")

```

### Decompiled Code

Now we have a pseudo code that makes sense

```c
loc_80100000: addi            sp, sp, -90h
loc_80100004: sd              s0, 88h+var_s0(sp)
loc_80100008: addi            s0, sp, 88h+arg_0
loc_80100010: la              a4, aWhatIsTheFlag# "What is the flag?"
loc_80100018: print a4
loc_80100024: li              a4, 1
loc_80100028: push a4
loc_80100034: li              a4, 2
loc_80100038: push a4
loc_80100044: pop a4
loc_80100048: li              a5, 2
loc_8010004c: bne             a4, a5, loc_80100064


loc_80100058: pop a4
loc_8010005c: li              a5, 1
loc_80100060: beq             a4, a5, loc_80100078


loc_80100068: la              a4, aWrong# "Wrong"
loc_80100070: print a4
loc_80100074: j               loc_801009D0


loc_80100078: nop
loc_8010007c: sd              zero, -8+var_10(s0)
loc_80100084: li              a4, 15
loc_80100088: push_call_1
loc_80100094: ld              a4, -8+var_10(s0)
loc_80100098: push a4
loc_801000a4: la              a4, qword_80101028
loc_801000ac: ld              a4, (qword_80101028 - 80101028h)(a4)
loc_801000b0: push a4
loc_801000c4: a4 = stack[-2] * stack[-1]
loc_801000c8: push a4
loc_801000d4: li              a4, 7
loc_801000d8: stack[-1] rol= a4
loc_801000e0: lui             a4, 28EC7h
loc_801000e4: slli            a4, a4, 2
loc_801000e8: addi            a4, a4, 2D3h
loc_801000ec: stack[-1] ^= a4
loc_801000f8: la              a4, qword_80101030
loc_80100100: ld              a4, (qword_80101030 - 80101030h)(a4)
loc_80100104: stack[-1] += a4
loc_80100110: pop a4
loc_80100114: sd              a5, -8+var_18(s0)
loc_80100120: ld              a4, -8+var_18(s0)
loc_80100124: push a4
loc_80100130: ld              a4, -8+var_18(s0)
loc_80100134: push a4
loc_80100140: li              a4, 2135587861
loc_80100148: push a4
loc_8010015c: a4 = stack[-2] + stack[-1]
loc_80100160: push a4
loc_8010016c: li              a4, 1859775393
loc_80100174: stack[-1] *= a4
loc_80100180: li              a4, 11
loc_80100184: stack[-1] rol= a4
loc_80100194: a4 = stack[-2] ^ stack[-1]
loc_80100198: push a4
loc_801001a4: lui             a4, 13C6Fh
loc_801001a8: slli            a4, a4, 3
loc_801001ac: addi            a4, a4, -647h
loc_801001b0: push a4
loc_801001bc: li              a4, 3
loc_801001c0: stack[-1] rol= a4
loc_801001cc: pop a4
loc_801001d0: sd              a5, -8+var_18(s0)
loc_801001dc: ld              a4, -8+var_18(s0)
loc_801001e0: push a4
loc_801001ec: ld              a4, -8+var_18(s0)
loc_801001f0: push a4
loc_80100204: a4 = stack[-2] + stack[-1]
loc_80100208: push a4
loc_80100214: lui             a4, 37AB7h
loc_80100218: slli            a4, a4, 2
loc_8010021c: addi            a4, a4, -111h
loc_80100220: push a4
loc_80100230: a4 = stack[-2] ^ stack[-1]
loc_80100234: push a4
loc_80100240: li              a4, 5
loc_80100244: stack[-1] rol= a4
loc_80100250: lui             a4, 16A53h
loc_80100254: slli            a4, a4, 3
loc_80100258: addi            a4, a4, -5B3h
loc_8010025c: stack[-1] *= a4
loc_80100268: li              a4, 1051962371
loc_80100270: slli            a4, a4, 2
loc_80100274: stack[-1] += a4
loc_80100280: li              a4, 13
loc_80100284: stack[-1] rol= a4
loc_80100294: a4 = stack[-2] ^ stack[-1]
loc_80100298: push a4
loc_8010029c: ld              a5, -8+var_10(s0)
loc_801002a0: addi            a5, a5, 1
loc_801002a4: sd              a5, -8+var_10(s0)
loc_801002ac: pop_call_1
loc_801002b0: sd              a5, -8+var_20(s0)
loc_801002bc: push a4
loc_801002c4: li              a4, 2
loc_801002c8: push_call_1
loc_801002d0: li              a4, 1
loc_801002d4: push_call_2
loc_801002dc: li              a4, 1
loc_801002e0: push_call_3
loc_801002ec: li              a4, 6
loc_801002f0: stack[-1] += a4
loc_801002f8: pop_call_3
loc_801002fc: sd              a5, -8+var_28(s0)
loc_80100304: pop_call_2
loc_80100308: sd              a5, -8+var_30(s0)
loc_80100310: pop_call_1
loc_80100314: sd              a5, -8+var_38(s0)
loc_80100320: li              a4, 8
loc_80100324: stack[-1] += a4
loc_80100334: pop a4
loc_80100338: push_call_1
loc_80100340: getchar a4
loc_80100344: sb              a5, -8+var_39(s0)
loc_80100348: lbu             a5, -8+var_39(s0)
loc_8010034c: andi            a4, a5, 0FFh
loc_80100350: li              a5, 10
loc_80100354: beq             a4, a5, loc_801003C4


loc_80100360: lbu             a4, -8+var_39(s0)
loc_80100364: push a4
loc_80100370: li              a4, -1
loc_80100374: push a4
loc_80100384: a4 = stack[-2] ^ stack[-1]
loc_80100388: push a4
loc_80100394: li              a4, 1
loc_80100398: stack[-1] += a4
loc_801003a4: pop a4
loc_801003ac: andi            a4, a4, 0FFh
loc_801003b0: encrypt a4
loc_801003b8: pop_call_1
loc_801003bc: sd              a5, -8+var_48(s0)
loc_801003c0: j               loc_801003C8


loc_801003c4: nop
loc_801003c8: li              a5, 1
loc_801003cc: sd              a5, -8+var_50(s0)
loc_801003d4: li              a4, 6
loc_801003d8: push_call_1
loc_801003e4: ld              a4, -8+var_50(s0)
loc_801003e8: push a4
loc_801003f4: ld              a4, -8+var_50(s0)
loc_801003f8: stack[-1] *= a4
loc_8010040c: a4 = rol stack[-2] stack[-1]
loc_80100410: push a4
loc_8010041c: ld              a4, -8+var_50(s0)
loc_80100420: push a4
loc_8010042c: li              a4, 1
loc_80100430: stack[-1] += a4
loc_8010043c: pop a4
loc_80100440: sd              a5, -8+var_50(s0)
loc_80100448: la              a4, qword_80101038
loc_80100450: ld              a4, (qword_80101038 - 80101038h)(a4)
loc_80100454: stack[-1] ^= a4
loc_80100460: pop a4
loc_80100464: sd              a5, -8+var_58(s0)
loc_80100470: pop a4
loc_80100474: sd              a5, -8+var_60(s0)
loc_80100480: li              a4, 3
loc_80100484: push a4
loc_80100490: ld              a4, -8+var_58(s0)
loc_80100494: push a4
loc_8010049c: ld              a4, -8+var_60(s0)
loc_801004a0: stack[-1] ^= a4
loc_801004b4: a4 = stack[-2] + stack[-1]
loc_801004b8: push a4
loc_801004c4: li              a4, -1
loc_801004c8: push a4
loc_801004d0: ld              a4, -8+var_58(s0)
loc_801004d4: stack[-1] ^= a4
loc_801004e0: li              a4, -1
loc_801004e4: push a4
loc_801004ec: ld              a4, -8+var_60(s0)
loc_801004f0: stack[-1] ^= a4
loc_80100504: a4 = stack[-2] | stack[-1]
loc_80100508: push a4
loc_80100514: li              a4, 3
loc_80100518: push a4
loc_8010052c: a4 = stack[-2] * stack[-1]
loc_80100530: push a4
loc_80100544: a4 = stack[-2] + stack[-1]
loc_80100548: push a4
loc_80100554: li              a4, -1
loc_80100558: push a4
loc_80100560: ld              a4, -8+var_58(s0)
loc_80100564: stack[-1] ^= a4
loc_80100570: li              a4, -1
loc_80100574: push a4
loc_8010057c: ld              a4, -8+var_60(s0)
loc_80100580: stack[-1] ^= a4
loc_80100594: a4 = stack[-2] | stack[-1]
loc_80100598: push a4
loc_801005a0: li              a4, -1
loc_801005a4: stack[-1] ^= a4
loc_801005b0: li              a4, 5
loc_801005b4: push a4
loc_801005c8: a4 = stack[-2] * stack[-1]
loc_801005cc: push a4
loc_801005e0: a4 = stack[-2] + stack[-1]
loc_801005e4: push a4
loc_801005ec: pop_call_1
loc_801005f0: sd              a5, -8+var_68(s0)
loc_801005fc: pop a4
loc_80100600: la              a5, qword_80101040
loc_80100608: ld              a5, (qword_80101040 - 80101040h)(a5)
loc_8010060c: beq             a4, a5, loc_80100634


loc_80100614: la              a4, aWrong# "Wrong"
loc_8010061c: print a4
loc_8010062c: pop a4
loc_80100630: exit


loc_80100634: li              a5, 4
loc_80100638: sd              a5, -8+var_70(s0)
loc_80100640: li              a4, 1
loc_80100644: push_call_2
loc_8010064c: ld              a4, -8+var_70(s0)
loc_80100650: push_call_1
loc_8010065c: ld              a4, -8+var_50(s0)
loc_80100660: push a4
loc_8010066c: ld              a4, -8+var_50(s0)
loc_80100670: stack[-1] *= a4
loc_80100684: a4 = rol stack[-2] stack[-1]
loc_80100688: push a4
loc_80100694: ld              a4, -8+var_50(s0)
loc_80100698: push a4
loc_801006a4: li              a4, 1
loc_801006a8: stack[-1] += a4
loc_801006b4: pop a4
loc_801006b8: sd              a5, -8+var_50(s0)
loc_801006c0: la              a4, qword_80101038
loc_801006c8: ld              a4, (qword_80101038 - 80101038h)(a4)
loc_801006cc: stack[-1] ^= a4
loc_801006d8: pop a4
loc_801006dc: sd              a5, -8+var_58(s0)
loc_801006e8: pop a4
loc_801006ec: sd              a5, -8+var_60(s0)
loc_801006f8: ld              a4, -8+var_60(s0)
loc_801006fc: push a4
loc_80100708: li              a4, 1
loc_8010070c: push a4
loc_80100718: ld              a4, -8+var_60(s0)
loc_8010071c: push a4
loc_80100728: li              a4, -1
loc_8010072c: push a4
loc_8010073c: a4 = stack[-2] ^ stack[-1]
loc_80100740: push a4
loc_80100754: a4 = stack[-2] + stack[-1]
loc_80100758: push a4
loc_80100764: ld              a4, -8+var_58(s0)
loc_80100768: stack[-1] += a4
loc_80100778: a4 = stack[-2] ^ stack[-1]
loc_8010077c: push a4
loc_80100784: ld              a4, -8+var_60(s0)
loc_80100788: stack[-1] ^= a4
loc_80100790: pop_call_1
loc_80100794: sd              a5, -8+var_78(s0)
loc_801007a0: pop a4
loc_801007a4: sd              a5, -8+var_80(s0)
loc_801007a8: ld              a4, -8+var_80(s0)
loc_801007ac: la              a5, qword_80101048
loc_801007b4: ld              a5, (qword_80101048 - 80101048h)(a5)
loc_801007b8: bne             a4, a5, loc_801007E4


loc_801007c4: ld              a4, -8+var_80(s0)
loc_801007c8: push a4
loc_801007cc: li              a5, 1
loc_801007d0: sd              a5, -8+var_70(s0)
loc_801007d8: pop_call_2
loc_801007dc: sd              a5, -8+var_88(s0)
loc_801007e0: j               loc_80100844


loc_801007e4: ld              a4, -8+var_80(s0)
loc_801007e8: la              a5, qword_80101050
loc_801007f0: ld              a5, (qword_80101050 - 80101050h)(a5)
loc_801007f4: bne             a4, a5, loc_80100820


loc_801007fc: la              a4, aCorrect# "Correct"
loc_80100804: print a4
loc_80100814: pop a4
loc_80100818: unknown_1973
loc_8010081c: j               loc_80100844


loc_80100824: la              a4, aWrong# "Wrong"
loc_8010082c: print a4
loc_8010083c: pop a4
loc_80100840: unknown_404
loc_80100848: li              a4, 991469
loc_80100850: push_call_1
loc_80100858: li              a4, 692549
loc_80100860: push_call_3
loc_80100868: li              a4, 823212
loc_80100870: push_call_2
loc_8010087c: li              a4, 31815
loc_80100884: push a4
loc_80100890: li              a4, 26492
loc_80100898: push a4
loc_801008a4: li              a4, 815730
loc_801008ac: push a4
loc_801008b8: li              a4, 469207
loc_801008c0: stack[-1] rol= a4
loc_801008c8: li              a4, 330825
loc_801008d0: stack[-1] ^= a4
loc_801008dc: li              a4, 66912
loc_801008e4: stack[-1] += a4
loc_801008f0: li              a4, 858794
loc_801008f8: stack[-1] *= a4
loc_80100904: li              a4, 329986
loc_8010090c: push a4
loc_80100918: li              a4, 67744
loc_80100920: push a4
loc_8010092c: li              a4, 24871
loc_80100934: stack[-1] *= a4
loc_8010093c: li              a4, 50
loc_80100940: encrypt a4
loc_80100948: li              a4, 155059
loc_80100950: print a4
loc_80100960: pop_call_2
loc_80100964: push a4
loc_80100974: pop_call_3
loc_80100978: push a4
loc_80100988: pop_call_1
loc_8010098c: push a4
loc_80100998: pop a4
loc_8010099c: la              a5, qword_80101058
loc_801009a4: ld              a5, (qword_80101058 - 80101058h)(a5)
loc_801009a8: bne             a4, a5, loc_801009C0


loc_801009b0: la              a4, aCorrect# "Correct"
loc_801009b8: print a4
loc_801009bc: j               loc_801009D0


loc_801009c4: la              a4, aWrong# "Wrong"
loc_801009cc: print a4
loc_801009d0: ld              s0, 88h+var_s0(sp)
loc_801009d4: addi            sp, sp, 90h
loc_801009d8: ret
```

## Solve

Now we can actually see a somewhat readable code.
We can start by noticing that the code is divided into 4 sections,
the first one is like it's checking that the vm is working properly, then there are two crc and the last one is probably a decoy given that it's doing 3 nested for loops of length 991469, 692549 and 823212, which would amount to 565 quadrillion that is not feasible.

We can now start to implement the `encrypt` function in python

```py
def flag_to_data(flag):
    memory_data = [
        0x70, 0x17, 0x58, 0x61, 0x76, 0x01, 0x00, 0x4e,
        0x45, 0xc7, 0xdf, 0xa9, 0xc2, 0xa3, 0x2a, 0xd6,
        0xf2, 0x3a, 0xca, 0x49, 0x39, 0xc0, 0xdb, 0x03,
        0x70, 0x72, 0x71, 0xea, 0x5f, 0xaa, 0xb7, 0x48,
        0x3a, 0xa1, 0x9b, 0x4e, 0x21, 0x3c, 0xa3, 0x39,
        0xbf, 0x15, 0x16, 0x81, 0x0a, 0xc7, 0xba, 0xfb,
        0x27, 0x50, 0x95, 0x39, 0xea, 0x7d, 0x6b, 0xc5,
        0x89, 0x03, 0x98, 0xbf, 0xf0, 0xd7, 0x99, 0xdb,
        0x30, 0x7c, 0xd7, 0x7a, 0x4b, 0xbf, 0xe1, 0x5e,
        0xb4, 0xb0, 0xc9, 0xc4, 0x31, 0xb6, 0x10, 0x5c,
        0x7f, 0xe6, 0xbc, 0x64, 0x9e, 0xdc, 0xe4, 0x89,
        0xc3, 0x5e, 0x1b, 0xcd, 0x01, 0x71, 0x29, 0x9d,
        0x6a, 0x8d, 0xed, 0x52, 0x33, 0xc2, 0x71, 0x02,
        0x46, 0x46, 0x0d, 0xc7, 0xe1, 0xde, 0x6c, 0xe1,
        0xef, 0xbb, 0x7f, 0x7b, 0x9c, 0xb7, 0x39, 0x1d,
        0x70, 0xeb, 0x02, 0x32, 0xe6, 0x61, 0x03, 0xdf,
    ]

    memory = memory_data[::] + [0] * 100

    buf_1 = 0x800060A0 - 0x800060A0
    buf_2 = 0x800060DF - 0x800060A0
    buf_3 = 0x800060E0 - 0x800060A0
    buf_4 = 0x8000611F - 0x800060A0

    for b in flag:
        b = (b ^ 0xff) + 1
        memory[buf_1] = b ^ 0x29
        memory[buf_2] = b - 82
        memory[buf_3] = b ^ ((memory[buf_2] - memory[buf_1]) & 0xFF)
        v71 = ((b & 0xFF) << 4) | ((b & 0xFF) >> 4)
        memory[buf_4] = v71 & 0xFF
        buf_1 += 1
        buf_2 -= 1
        buf_3 += 1
        buf_4 -= 1

    qwords = []
    for addr in range(0, 128, 16):
        bytes_data = []
        for i in range(16):
            bytes_data.append(memory[addr + i])

        qword1 = 0
        qword2 = 0
        for i in range(8):
            qword1 |= (bytes_data[i] << (i * 8))
            qword2 |= (bytes_data[i + 8] << (i * 8))

        qwords.append(qword1)
        qwords.append(qword2)

    return qwords
```

Then we can follow up with the first CRC

```py
def rot_l(x, n):
    n %= 64
    x = ((x << n) | (x >> (64-n)) & 0xFFFFFFFFFFFFFFFF)
    return x & 0xFFFFFFFFFFFFFFFF


def crc1(data):
    for i in range(1, 8):
        data[-i] = rot_l(data[-i], i ** 2) ^ 0x9E3779B97F4A7C15

        local_60 = data[-i]
        local_68 = data[-i - 1]

        data[-i - 1] = ((((local_60 ^ local_68) + 3) & 0xFFFFFFFFFFFFFFFF) +
                        ((((local_60 ^ 0xFFFFFFFFFFFFFFFF) | (
                                    local_68 ^ 0xFFFFFFFFFFFFFFFF)) * 3) & 0xFFFFFFFFFFFFFFFF) +
                        ((((local_60 ^ 0xFFFFFFFFFFFFFFFF) | (
                                    local_68 ^ 0xFFFFFFFFFFFFFFFF)) ^ 0xFFFFFFFFFFFFFFFF) * 5) & 0xFFFFFFFFFFFFFFFF)

        data[-i - 1] &= 0xFFFFFFFFFFFFFFFF

    return data[0]
```

Lastly the second CRC

```py
def crc2(data):
    i = 8

    for _ in range(5):
        data[-1] = rot_l(data[-1], i ** 2) ^ 0x9E3779B97F4A7C15
        i += 1

        local_60 = data[-1]
        local_68 = data[-2]
        data = data[:-2]

        data.append((local_68 ^ 0xFFFFFFFFFFFFFFFF) + 1 + local_60)
        data[-1] &= 0xFFFFFFFFFFFFFFFF

    s.add(data[-1] == 0x0796DCF410F11057)

    for _ in range(2):
        data[-1] = rot_l(data[-1], i ** 2) ^ 0x9E3779B97F4A7C15
        i += 1

        local_60 = data[-1]
        local_68 = data[-2]
        data = data[:-2]

        data.append((local_68 ^ 0xFFFFFFFFFFFFFFFF) + 1 + local_60)
        data[-1] &= 0xFFFFFFFFFFFFFFFF

    return data
```

Now we need to add the constraints from the original code

```py
blocks = flag_to_data(flag)
s.add(crc1(blocks[8:]) == 0x37FBE21EAE04066A)

data = crc2(blocks[:8])
x = data.pop()
s.add(x == 0x5F36D6201C352A7A)
```


### Final Script

Now by assembling the previous snippets together we get the final solve script (plus the z3 "boilerplate" for the symbolic flag).

The only missing piece was the **flag length**. Since it wasn't explicitly checked or enforced in the binary, we attached GDB and set a breakpoint on getchar to observe how many characters were being read. The program attempted to read up to **0x50** characters + '\n' (**80** characters, which seemed quite long for a flag), so, instead of assuming that was the real length, we bruteforced the correct one in the script by trying all possible values until we found one that satisfied all constraints.

```py
from z3 import *


def flag_to_data(flag):
    memory_data = [
        0x70, 0x17, 0x58, 0x61, 0x76, 0x01, 0x00, 0x4e,
        0x45, 0xc7, 0xdf, 0xa9, 0xc2, 0xa3, 0x2a, 0xd6,
        0xf2, 0x3a, 0xca, 0x49, 0x39, 0xc0, 0xdb, 0x03,
        0x70, 0x72, 0x71, 0xea, 0x5f, 0xaa, 0xb7, 0x48,
        0x3a, 0xa1, 0x9b, 0x4e, 0x21, 0x3c, 0xa3, 0x39,
        0xbf, 0x15, 0x16, 0x81, 0x0a, 0xc7, 0xba, 0xfb,
        0x27, 0x50, 0x95, 0x39, 0xea, 0x7d, 0x6b, 0xc5,
        0x89, 0x03, 0x98, 0xbf, 0xf0, 0xd7, 0x99, 0xdb,
        0x30, 0x7c, 0xd7, 0x7a, 0x4b, 0xbf, 0xe1, 0x5e,
        0xb4, 0xb0, 0xc9, 0xc4, 0x31, 0xb6, 0x10, 0x5c,
        0x7f, 0xe6, 0xbc, 0x64, 0x9e, 0xdc, 0xe4, 0x89,
        0xc3, 0x5e, 0x1b, 0xcd, 0x01, 0x71, 0x29, 0x9d,
        0x6a, 0x8d, 0xed, 0x52, 0x33, 0xc2, 0x71, 0x02,
        0x46, 0x46, 0x0d, 0xc7, 0xe1, 0xde, 0x6c, 0xe1,
        0xef, 0xbb, 0x7f, 0x7b, 0x9c, 0xb7, 0x39, 0x1d,
        0x70, 0xeb, 0x02, 0x32, 0xe6, 0x61, 0x03, 0xdf,
    ]

    memory = memory_data[::] + [0] * 100

    buf_1 = 0x800060A0 - 0x800060A0
    buf_2 = 0x800060DF - 0x800060A0
    buf_3 = 0x800060E0 - 0x800060A0
    buf_4 = 0x8000611F - 0x800060A0

    for b in flag:
        b = (b ^ 0xff) + 1
        memory[buf_1] = b ^ 0x29
        memory[buf_2] = b - 82
        memory[buf_3] = b ^ ((memory[buf_2] - memory[buf_1]) & 0xFF)
        v71 = ((b & 0xFF) << 4) | ((b & 0xFF) >> 4)
        memory[buf_4] = v71 & 0xFF
        buf_1 += 1
        buf_2 -= 1
        buf_3 += 1
        buf_4 -= 1

    qwords = []
    for addr in range(0, 128, 16):
        bytes_data = []
        for i in range(16):
            bytes_data.append(memory[addr + i])

        qword1 = 0
        qword2 = 0
        for i in range(8):
            qword1 |= (bytes_data[i] << (i * 8))
            qword2 |= (bytes_data[i + 8] << (i * 8))

        qwords.append(qword1)
        qwords.append(qword2)

    return qwords


def rot_l(x, n):
    n %= 64
    x = ((x << n) | (x >> (64-n)) & 0xFFFFFFFFFFFFFFFF)
    return x & 0xFFFFFFFFFFFFFFFF


def crc1(data):
    for i in range(1, 8):
        data[-i] = rot_l(data[-i], i ** 2) ^ 0x9E3779B97F4A7C15

        local_60 = data[-i]
        local_68 = data[-i - 1]

        data[-i - 1] = ((((local_60 ^ local_68) + 3) & 0xFFFFFFFFFFFFFFFF) +
                        ((((local_60 ^ 0xFFFFFFFFFFFFFFFF) | (
                                    local_68 ^ 0xFFFFFFFFFFFFFFFF)) * 3) & 0xFFFFFFFFFFFFFFFF) +
                        ((((local_60 ^ 0xFFFFFFFFFFFFFFFF) | (
                                    local_68 ^ 0xFFFFFFFFFFFFFFFF)) ^ 0xFFFFFFFFFFFFFFFF) * 5) & 0xFFFFFFFFFFFFFFFF)

        data[-i - 1] &= 0xFFFFFFFFFFFFFFFF

    return data[0]


def crc2(data):
    i = 8

    for _ in range(5):
        data[-1] = rot_l(data[-1], i ** 2) ^ 0x9E3779B97F4A7C15
        i += 1

        local_60 = data[-1]
        local_68 = data[-2]
        data = data[:-2]

        data.append((local_68 ^ 0xFFFFFFFFFFFFFFFF) + 1 + local_60)
        data[-1] &= 0xFFFFFFFFFFFFFFFF

    s.add(data[-1] == 0x0796DCF410F11057)

    for _ in range(2):
        data[-1] = rot_l(data[-1], i ** 2) ^ 0x9E3779B97F4A7C15
        i += 1

        local_60 = data[-1]
        local_68 = data[-2]
        data = data[:-2]

        data.append((local_68 ^ 0xFFFFFFFFFFFFFFFF) + 1 + local_60)
        data[-1] &= 0xFFFFFFFFFFFFFFFF

    return data


for length in range(10, 0x50, 1): # 32
    flag = [BitVec(f'flag_{i}', 64) for i in range(length)]
    s = Solver()

    for i in range(len(flag)):
        s.add(flag[i] >= 48, flag[i] <= 125)

    s.add(flag[0] == ord('u'))
    s.add(flag[1] == ord('i'))
    s.add(flag[2] == ord('u'))
    s.add(flag[3] == ord('c'))
    s.add(flag[4] == ord('t'))
    s.add(flag[5] == ord('f'))
    s.add(flag[6] == ord('{'))
    s.add(flag[-1] == ord('}'))

    blocks = flag_to_data(flag)

    s.add(crc1(blocks[8:]) == 0x37FBE21EAE04066A)

    data = crc2(blocks[:8])
    x = data.pop()
    s.add(x == 0x5F36D6201C352A7A)

    print('Checking...', length)
    res = s.check()
    if res == sat:
        model = s.model()
        print("Solution found:")
        result = [chr(model[flag[i]].as_long()) if str(model[flag[i]]) != "None" else '?' for i in range(length)]
        print(''.join(result))
    else:
        print(res)
```

We can now wait until the correct len is found (which is 32) and we win.

## Flag

`uiuctf{M3m0Ry_M4ppED_SysTEmca11}`
