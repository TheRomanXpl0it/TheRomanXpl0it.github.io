---
title: Srdnlen CTF 2025 - It's not what it seems
date: '2025-01-19'
lastmod: '2025-01-20T12:55:24+02:00'
categories:
- writeup
- srdnlen25
tags:
- reverse
authors:
- ice cream
---

At first glance the challenge seems pretty standard, a flag checker, so after opening the binary with IDA, the following main function is showed:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  __int64 v5; // rax
  unsigned int v6; // eax
  int v7; // [rsp+Ch] [rbp-874h] BYREF
  _BYTE v8[1024]; // [rsp+10h] [rbp-870h] BYREF
  __int64 v9; // [rsp+410h] [rbp-470h]
  __int64 v10; // [rsp+418h] [rbp-468h]
  __int64 v11; // [rsp+420h] [rbp-460h]
  _QWORD v12[3]; // [rsp+428h] [rbp-458h]
  char s[1024]; // [rsp+440h] [rbp-440h] BYREF
  _BYTE v14[16]; // [rsp+840h] [rbp-40h] BYREF
  _BYTE v15[32]; // [rsp+850h] [rbp-30h] BYREF
  __int64 v16; // [rsp+870h] [rbp-10h]
  int v17; // [rsp+87Ch] [rbp-4h]

  if ( (unsigned int)RAND_bytes(v15, 32LL, envp) )
  {
    if ( (unsigned int)RAND_bytes(v14, 16LL, v3) )
    {
      printf("FLAG: ");
      fgets(s, 1024, _bss_start);
      s[strcspn(s, "\n")] = 0;
      v9 = 0x3B2E252C2E243233LL;
      v10 = 0x32341F327336732ELL;
      v11 = 0x1F7328141F347535LL;
      v12[0] = 0x2E35261F2E71742DLL;
      *(_QWORD *)((char *)v12 + 6) = 0x3D2E707134232E35LL;
      v17 = 0;
      v16 = EVP_CIPHER_CTX_new();
      if ( v16 )
      {
        v5 = EVP_aes_256_cbc();
        if ( (unsigned int)EVP_EncryptInit_ex(v16, v5, 0LL, v15, v14) == 1 )
        {
          v7 = 0;
          v6 = strlen(s);
          if ( (unsigned int)EVP_EncryptUpdate(v16, v8, &v7, s, v6) == 1 )
          {
            v17 += v7;
            if ( (unsigned int)EVP_EncryptFinal_ex(v16, &v8[v7], &v7) == 1 )
            {
              v17 += v7;
              EVP_CIPHER_CTX_free(v16);
              puts("Nope!");
              return 0;
            }
            else
            {
              fwrite("Error finalizing encryption.\n", 1uLL, 0x1DuLL, stderr);
              EVP_CIPHER_CTX_free(v16);
              return 1;
            }
          }
          else
          {
            fwrite("Error during encryption.\n", 1uLL, 0x19uLL, stderr);
            EVP_CIPHER_CTX_free(v16);
            return 1;
          }
        }
        else
        {
          fwrite("Error initializing encryption.\n", 1uLL, 0x1FuLL, stderr);
          EVP_CIPHER_CTX_free(v16);
          return 1;
        }
      }
      else
      {
        fwrite("Error creating context.\n", 1uLL, 0x18uLL, stderr);
        return 1;
      }
    }
    else
    {
      fwrite("Error generating random IV.\n", 1uLL, 0x1CuLL, stderr);
      return 1;
    }
  }
  else
  {
    fwrite("Error generating random key.\n", 1uLL, 0x1DuLL, stderr);
    return 1;
  }
}
```

This is really a strange function, because, there is no flag check, so the first thounght is to check the **.init_array** section for global constructors, but it ends up without functions.
The next step is to set a breakpoint on the `EVP_EncryptFinal_ex` function call to see what is happening. But this breakpoint is never being triggered, so we know that something strange is happening, and after a quick realization we can find that the _start function is not the standard one:

```c
void __noreturn start()
{
  signed __int64 v0; // rax
  const char **v1; // rdx
  const char *v2; // rsi
  __int64 v3; // rcx
  _BYTE *key; // rdi
  __int64 v5; // rax
  signed __int64 v6; // rax
  signed __int64 v7; // rax
  __int64 buf; // [rsp+0h] [rbp-8h] BYREF

  v0 = sys_mprotect((unsigned __int64)main & 0xFFFFFFFFFFFFF000LL, 0x1000uLL, 7uLL);
  v2 = (const char *)main;
  v3 = 342LL;
  key = &keys;
  do
  {
    *v2++ ^= *key++;
    --v3;
  }
  while ( v3 );
  LODWORD(v5) = main((int)key, (const char **)v2, v1);
  if ( v5 )
  {
    buf = '!seY';
    v6 = sys_write(1u, (const char *)&buf, 4uLL);
  }
  v7 = sys_exit(0);
}
```

As what we can see by the decopiled code of IDA, the start is *decrypting* the main, so we can set a breakpoint on the **main** function call to see it decrypted:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // rdi
  _BYTE *i; // rsi
  _QWORD v6[3]; // [rsp+410h] [rbp-470h] BYREF
  _QWORD v7[3]; // [rsp+428h] [rbp-458h]
  char in[1024]; // [rsp+440h] [rbp-440h] BYREF
  _BYTE iv[16]; // [rsp+840h] [rbp-40h] BYREF
  _BYTE key[32]; // [rsp+850h] [rbp-30h] BYREF

  if ( (unsigned int)RAND_bytes(key, 32LL) )
  {
    if ( (unsigned int)RAND_bytes(iv, 16LL) )
    {
      printf("FLAG: ");
      fgets(in, 1024, _bss_start);
      v4 = in;
      in[strcspn(in, "\n")] = 0;
      v6[0] = 0x3B2E252C2E243233LL;
      v6[1] = 0x32341F327336732ELL;
      v6[2] = 0x1F7328141F347535LL;
      v7[0] = 0x2E35261F2E71742DLL;
      result = 0x34232E35;
      *(_QWORD *)((char *)v7 + 6) = 0x3D2E707134232E35LL;
      for ( i = v6; ; ++i )
      {
        LOBYTE(result) = *i;
        if ( (*i ^ (unsigned __int8)*v4) != 64 )
          break;
        ++v4;
        if ( (_BYTE)result == 61 )
          return result;
      }
      puts("Nope!");
      return 0;
    }
    else
    {
      fwrite("Error generating random IV.\n", 1uLL, 0x1CuLL, stderr);
      return 1;
    }
  }
  else
  {
    fwrite("Error generating random key.\n", 1uLL, 0x1DuLL, stderr);
    return 1;
  }
}
```

As we can see, the decrypted function is actually checking the flag by xorring the strange bytes that we saw earlier with the input to get **64** (0x40), so we can reverse he operation and flag:

```py
from pwn import xor
from Crypto.Util.number import long_to_bytes

flag = [
	0x3B2E252C2E243233,
	0x32341F327336732E,
	0x1F7328141F347535,
	0x2E35261F2E71742D,
	0x3D2E707134232E35,
]

flag = b''.join([long_to_bytes(i) for i in flag[::-1]])

print(xor(flag, 0x40)[::-1])
```

this takes out the following flag: `srdnlen{n3v3r_tru5t_Th3_m41n_fununct10n}` which is wrong, but we can fix it by removing the extra **un** in **fununct10n** to get the real flag `srdnlen{n3v3r_tru5t_Th3_m41n_funct10n}`
