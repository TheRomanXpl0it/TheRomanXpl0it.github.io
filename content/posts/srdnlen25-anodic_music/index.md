---
title: Srdnlen CTF 2025 - Anodic Music
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

As always we can start by decompiling the main function:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *dialogue; // rax
  int i; // [rsp+Ch] [rbp-64h]
  void *v6; // [rsp+10h] [rbp-60h]
  s_bank *bank; // [rsp+18h] [rbp-58h]
  char input[68]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 canary; // [rsp+68h] [rbp-8h]

  canary = __readfsqword(0x28u);
  memset(input, 0, 62);
  v6 = malloc(0x10uLL);
  bank = load_bank();
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  for ( i = 0; i <= 61; ++i )
  {
    dialogue = get_dialogue();
    printf("%s", dialogue);
    input[i] = getc(stdin);
    getc(stdin);
    md5String(input, v6);
    if ( (unsigned __int8)lookup_bank(v6, bank) )
    {
      puts("There has to be some way to talk to this person, you just haven't found it yet.");
      return -1;
    }
  }
  printf("Hey it looks like you have input the right flag. Why are you still here?");
  return 0;
}
```

We can now analyze the following not known functions, starting from `load_bank`:

```c
_QWORD *load_bank()
{
  _QWORD *result; // rax
  FILE *stream; // [rsp+0h] [rbp-20h]
  __int64 size; // [rsp+8h] [rbp-18h]
  void *bank; // [rsp+10h] [rbp-10h]

  stream = fopen("hardcore.bnk", "rb");
  fseek(stream, SEEK_SET, SEEK_END);
  size = ftell(stream);
  rewind(stream);
  bank = malloc(size);
  fread(bank, size, 1uLL, stream);
  fclose(stream);
  result = malloc(0x10uLL);
  *result = size;
  result[1] = bank;
  return result;
}
```

As we can see, it is loading the other file that was given to us and loading is what it seems a struct that we can define as:

```c
struct s_bank // sizeof=0x10
{
    __int64 size;
    char *bank;
};
```

Now we can continue by looking into `get_dialogue`, which is pretty useless:

```c
char *get_dialogue()
{
  char ptr; // [rsp+Fh] [rbp-11h] BYREF
  FILE *stream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stream = fopen("/dev/urandom", "rb");
  fread(&ptr, 1uLL, 1uLL, stream);
  return (&dialogue)[ptr & 0xF];
}
```

Then we have `md5String`:

```c
unsigned __int64 __fastcall md5String(const char *input, char *out)
{
  size_t size; // rax
  __int64 v3; // rdx
  MD5Context ctx; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 canary; // [rsp+78h] [rbp-8h]

  canary = __readfsqword(0x28u);
  md5Init((__int64)&ctx);
  size = strlen(input);
  md5Update(&ctx, input, size);
  md5Finalize(&ctx);
  v3 = *(_QWORD *)&ctx.digest[8];
  *(_QWORD *)out = *(_QWORD *)ctx.digest;
  *((_QWORD *)out + 1) = v3;
  return canary - __readfsqword(0x28u);
}
```

Which is doing an md5sum with a library like [https://github.com/Zunawe/md5-c](https://github.com/Zunawe/md5-c), where we can extract the context type for better reversing:

```c
struct MD5Context // sizeof=0x68
{                                       // XREF: md5String/r
    uint64_t size;
    uint32_t buffer[4];
    uint8_t input[64];
    uint8_t digest[16];                 // XREF: md5String+5D/r
                                        // md5String+61/r
};
```

And lastly we have `lookup_bank` which is checking if the hash is into the given bank of hashes

```c
__int64 __fastcall lookup_bank(const void *a1, s_bank *a2)
{
  __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0LL; i < a2->size / 16; ++i )
  {
    if ( !memcmp(a1, &a2->bank[16 * i], 0x10uLL) )
      return 1LL;
  }
  return 0LL;
}
```

So, after reversing all the functions we can say that the main, after loading the bank into memory, i doing the hash of the current char that is read from the user and checking if into the bank, so we can think of try manualy some characters knowing that the flag format is `srdnlen{`, but after some tries we can see that also other characters are valid (like *t* is valid, but the first char should be *s*), so we are analyzing a **trie** like data structure that we can explore with a **dfs**:

```py
from string import printable
from hashlib import md5

with open('hardcore.bnk', 'rb') as f:
	data = f.read()

hashes = [data[i*16:(i+1)*16] for i in range(len(data)//16)]

flag = 'srdnlen{'

def dfs(flag):
	if len(flag) == 63:
		exit(0)

	for c in printable[:-6]:
		tmp = flag + c
		digest = md5(tmp.encode()).digest()
		if digest not in hashes:
			print(tmp)
			dfs(tmp)


dfs(flag)
```

After running the whole script we get the flag: `srdnlen{Mr_Evrart_is_helping_me_find_my_flag_af04993a13b8eecd}`
