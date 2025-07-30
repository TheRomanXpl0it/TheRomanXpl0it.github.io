---
title: UIUCTF 25 - flag_checker
date: '2025-07-29T11:15:30+02:00'
math: false
categories:
- writeup
- uiuctf25
tags:
- reverse
- cuda
authors:
- ice cream
---

## Description

Another flag checker challenge...can you get the correct input to print out the flag?

author: epistemologist

## Analysis

We start by opening the binary attachment with IDA, from there I can see that the main is fairly simple, it reads an input, runs some checks and then prints the flag.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  get_input(v4, argv, envp);
  if ( (unsigned __int8)check_input((__int64)v4) )
  {
    puts("PRINTING FLAG: ");
    print_flag(v4);
  }
  return 0;
}
```

First we take a look to the `print_flag` function to see that it takes our input as "key" to decrypt the flag and print it

```c
unsigned __int64 __fastcall print_flag(__int64 a1)
{
  int i; // [rsp+1Ch] [rbp-44h]
  _DWORD v3[14]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v4; // [rsp+58h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 7; ++i )
    v3[i] = F(flag_enc[i], *(unsigned int *)(4LL * i + a1), 0xFFFFFF2FLL);
  printf("sigpwny{%s}", (const char *)v3);
  return v4 - __readfsqword(0x28u);
}
```

We can now check the content of the function `F`, discovering that it is the fast exponentiation function

```c
__int64 __fastcall F(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned __int64 v5; // [rsp+18h] [rbp-10h]
  unsigned __int64 v6; // [rsp+20h] [rbp-8h]

  v5 = 1LL;
  v6 = a1 % a3;
  while ( a2 > 0 )
  {
    if ( (a2 & 1) != 0 )
      v5 = v6 * v5 % a3;
    v6 = v6 * v6 % a3;
    a2 >>= 1;
  }
  return v5;
}
```

Now we can finally see the `check_input` function

```c
__int64 __fastcall check_input(__int64 a1)
{
  int i; // [rsp+10h] [rbp-8h]

  for ( i = 0; i <= 7; ++i )
  {
    if ( (unsigned int)F(test_pt[i], *(unsigned int *)(4LL * i + a1), 0xFFFFFF2FLL) != test_ct[i] )
      return 0LL;
  }
  return 1LL;
}
```

As we can see, it's doing `pow(test_pt[i], a1[i], 0xFFFFFF2FLL) != test_ct[i]` where `a1` are 4 bytes of the key, so now we can take the constants from IDA

```c
.rodata:0000000000002040                 public test_pt
.rodata:0000000000002040 ; unsigned int test_pt[8]
.rodata:0000000000002040 test_pt         dd 2265B1F5h, 91B7584Ah, 0D8F16ADFh, 0CD613E30h, 0C386BBC4h
.rodata:0000000000002040                                         ; DATA XREF: check_input+45↑o
.rodata:0000000000002054                 dd 1027C4D1h, 414C343Ch, 1E2FEB89h
.rodata:0000000000002060                 public test_ct
.rodata:0000000000002060 ; _DWORD test_ct[8]
.rodata:0000000000002060 test_ct         dd 0DC44BF5Eh, 5AFF1CECh, 0E1E9B4C2h, 1329B92h, 8F9CA92Ah
.rodata:0000000000002060                                         ; DATA XREF: check_input+6F↑o
.rodata:0000000000002074                 dd 0E45C5B4h, 604A4B91h, 7081EB59h
.rodata:0000000000002080                 public flag_enc
.rodata:0000000000002080 ; unsigned int flag_enc[8]
.rodata:0000000000002080 flag_enc        dd 24189111h, 0FD94E945h, 1B9F64A6h, 7FECE9A3h, 0FC2A0EDEh
.rodata:0000000000002080                                         ; DATA XREF: print_flag+54↑o
.rodata:0000000000002094                 dd 576EDCF5h, 1E44C9Ch, 658AF790h
```

now, we know that we should do a discrete log, but I'm a revver, not a cryptoer, so I can do it in another way.... Bruteforce with CUDA 🔥

## Solve

```cpp
#include <iostream>
#include <cuda.h>
#include <curand_kernel.h>


typedef unsigned long long ull;

__device__ ull test_pt[] = {0x2265B1F5LL, 0x91B7584ALL, 0x0D8F16ADFLL, 0x0CD613E30LL, 0x0C386BBC4LL, 0x1027C4D1LL, 0x414C343CLL, 0x1E2FEB89LL};
__device__ ull test_ct[] = {0x0DC44BF5ELL, 0x5AFF1CECLL, 0x0E1E9B4C2LL, 0x1329B92LL, 0x8F9CA92ALL, 0x0E45C5B4LL, 0x604A4B91LL, 0x7081EB59LL};


__device__ ull F(ull a1, ull a2, ull a3) {
	ull v5;
	ull v6;

	v5 = 1LL;
	v6 = a1 % a3;
	while ( a2 > 0 )
	{
		if ( (a2 & 1) != 0 )
			v5 = v6 * v5 % a3;
		v6 = v6 * v6 % a3;
		a2 >>= 1;
	}
	return v5;
}

__global__ void	brute() {
	ull exp = threadIdx.x + (blockIdx.x + (blockIdx.y + blockIdx.z * 256) * 256) * 256;
	for ( int i = 0; i <= 7; ++i ){
		if (F(test_pt[i], exp, 0xFFFFFF2FLL) == test_ct[i] ) {
			printf("Found: %d %016llx\n", i, exp);
		}
	}
}

int main() {
	dim3	blocks(256, 256, 256);
	dim3	threads(256);

	brute<<<blocks, threads>>>();
	cudaGetLastError();
	cudaDeviceSynchronize();
}
```

This will output the following:
```
Found: 4 0000000035bf992d
Found: 5 0000000063ca828d
Found: 1 000000007311d8a3
Found: 2 0000000078e51061
Found: 0 000000007ed4d57b
Found: 3 00000000a6cecc1b
Found: 6 00000000c324c985
Found: 7 00000000c4647159
Found: 2 00000000f8e50ff8
```

We can now take them (except the duplicate for "2") and win

```py
found = [None] * 8

found[4] = int("35bf992d", 16)
found[5] = int("63ca828d", 16)
found[1] = int("7311d8a3", 16)
found[2] = int("78e51061", 16)
found[0] = int("7ed4d57b", 16)
found[3] = int("a6cecc1b", 16)
found[6] = int("c324c985", 16)
found[7] = int("c4647159", 16)
# found[2] = int("f8e50ff8", 16)

enc = [0x24189111, 0xFD94E945, 0x1B9F64A6, 0x7FECE9A3, 0xFC2A0EDE, 0x576EDCF5, 0x1E44C9C, 0x658AF790]

print('sigpwny{', end='')
for i in range(8):
	block = hex(pow(enc[i], found[i], 0xFFFFFF2F))[2:]
	print(bytes.fromhex(block)[::-1].decode(), end='')
print('}')
```

Flag: `sigpwny{CrackingDiscreteLogs4TheFun/Lols}`
