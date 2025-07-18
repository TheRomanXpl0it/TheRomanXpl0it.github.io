---
title: WCTF 2019 BabyPwn
date: '2019-07-06'
lastmod: '2019-07-06T15:08:55+02:00'
categories:
- articles
tags:
- pwn
- crypto
authors:
- andreafioraldi
- chq-matteo
---

We played WCTF 2019 as mhackeroni and we got 8th place with two almost finished challenges that we could not submit in time.

We got first blood and the only solve on the BabyPwn challenge.

We imagine that many teams were close to the solution and so we will explain our solution that surprisingly worked.

Fun fact: we solved it at 4 a.m., after that the "a bit drunk man" Andrea returned early to home at 2 a.m. under the solicitation of "a bit competitive man" Matteo.

## PWN part

### Reversing

The binary is a PE32 for Windows.
The main function is located at 0x12FB0, IDA does not recognize it but it can be easily recognized going backward using the XREFs from the strings.
After a bit of reverse engineering, all the functions corresponding to each functionality can be found.
Note that the MD5 hashing service is completely useless.
Diggin in the code a custom readline routine (0x12EA0) is used many times.
This is the decompiled code:

```c
int __cdecl readline(char *a1, int size)
{
  int result; // eax
  int i; // [esp+4Ch] [ebp-8h]
  char v4; // [esp+50h] [ebp-4h]

  __maybe_cfg_shit__((int)&unk_1D035);
  for ( i = 0; ; ++i )
  {
    result = getchar();
    v4 = result;
    if ( result == '\n' )
      break;
    result = i;
    if ( i >= size )
      break;
    a1[i] = v4;
  }
  return result;
}
```

As you can easily see this function is buggy, the NUL terminator is not placed.

Looking in the join routine we can see that this function reads the username and the password and the username is a global variable.

Let’s look at this snipped from such procedure:

```c
  puts("[2]Input user info");
  print((int)"Username: ", v4);
  j_readline(username, 16);
  print((int)"Password: ", v1);
  j_readline(password, 10);
  puts("Message: ");
  puts("a.WCTF2019");
  puts("b.CyKOR");
  print((int)"> ", v2);
  j_readline(&a1, 1);
  if ( a1 == 'a' )
  {
    useless_shit = (int)"WCTF2019";
  }
  else
  {
    if ( a1 != 'b' )
      return puts("[!]Not available");
    useless_shit = (int)"CyKOR";
  }
```

You may also have noted the “useless_shit” shit, yeah this is a global variable just after username and it is placed to allow us to leak the binary base address.
Filling the username with “a”*16 and then printing the username we will have a leak of an address in the .rdata section of the binary. username is printed at the end of the login routine.

Now we have a leak, but how we can get EIP control? Not with this vulnerability for sure.

The next vulnerability is pretty clear, for a “babypwner”.
Look at the submit routine:

```c
int submit()
{
  int result; // eax
  char v1; // ST0C_1
  char v2; // [esp+0h] [ebp-5Ch]
  signed int i; // [esp+4Ch] [ebp-10h]
  char Dst; // [esp+50h] [ebp-Ch]

  _theread_id_something__((int)&xxx);
  j_memset(&Dst, 0, 10u);
  puts("[*]Submit");
  puts("Me: I think this draft is cool enough.");
  result = puts("Me: Let's submit this masterpiece.");
  if ( dh_value_1 && dh_value_2 >= 32 )
  {
    for ( i = 0; i < 32; ++i )
    {
      result = i + dh_value_1;
      if ( *(unsigned __int8 *)(i + dh_value_1) != i + 1 )
        return result;
    }
    puts("Validation complete.");
    print((int)"Student ID: ", v2);
    getchar();
    j_readline(&Dst, 40);
    puts(&null_str);
    result = print((int)"[+]Done!", v1);
  }
  return result;
}
```

The Dst buffer on the stack is only 10 bytes and readline is called with 40 bytes as size argument. This is a clear stack buffer overflow. But how we can trigger it? There is a check based on the values computed by the Diffie Hellman part that we didn’t have analyzed yet.
So we patch the check in the debugger and in our mind and we will return on it later.

### Exploitation

The offset from Dest to the return address if 16 bytes and so can insert a ropchain of 28 bytes. We divide the exploit in two different steps done in two execution of the program. Luckily, ASLR in Windows is done at boot and we can use the first connection to leak the kernel32.dll base address and it will be the same also for the next connection.

The first ropchain simply print the contents of an .idata entry associated to a routine in kernel32. We choose GetProcessHeap.
Note that we will not leak the address of GetProcessHeap but of the stub (always in kernel32) that jumps to GetProcessHeap.

In the second stage, we have only to exploit again the BOF in submit() and execute WinExec(“some command”, 0).
This requires only 16 bytes because we can insert the command as username (we know the address of the .data section of the binary) and use it as the first parameter for WinExec.

Returning to the missed part, the check based on Diffie Hellman was the real struggle of this cryptopwn.

## Cryptography part

### Objective

To exploit the BOF in function submit we have to pass a validation check

```c
  if ((SharedKey != 0) && (0x1f < _authed)) {
    i = 0;
    while (i < 0x20) {
      if ((uint)*(byte *)(SharedKey + i) != i + 1U) {
        return;
      }
      i = i + 1;
    }
    puts("Validation complete.");
```

SharedKey is a global variable that is set if we conclude correctly the "Diffie-hellman Key exchange" (option 1 of the Main menu)

This check requires SharedKey to be equal to 0102030405060708091011121314151617181920212223242526272829303132 when hex encoded.

To do so we have to carefully choose the parameters of the DH key exchange.

### Challenge overview

In function dh_exchange at 0x00411ae0 we are asked for 3 hex-encoded values

```
p (in hexadecimal, length <= 1000) : 
q (in hexadecimal, length <= 1000) :
g (in hexadecimal, 0x2 <= g <= 0x40 ) :
```

The three values are parsed and then passed to function key_exchange@0x00411f50

```
// function dh_exchange@0x00411ce1
...
  iVar1 = key_exchange(shared_secret,int_g,int_p,int_q);
  if (iVar1 == 0) {
    thunk_FUN_004124e0("DH key exchange failed.\n",unaff_DI);
    result = -1;
  }
  else {
    thunk_FUN_004124e0("DH key exchange succeeded!\n",unaff_DI);
….
```

If the exchange completes with success _authed and SharedKey will be set to come non zero value.

To at least complete the exchange, our parameters p, q, g need to satisfy some conditions:

1. q must be at least 0x200 bits long
2. q must divide p - 1
3. p, q must be prime

```c
// function key_exchange@0x00411fc6
    ….
  q_bit_len_ge_200 = __gmpz_sizeinbase(q,2);
  if (q_bit_len_ge_200 < 0x200) {
    return 0;
  }
  
    ….

p_min_1_mod_q = __gmpz_divisible_p(p_minus_1,q);
  if (p_min_1_mod_q == 0) {
    return 0;
  }

    ….

  is_prime = rabin_miller(p);
  if ((is_prime != 0) && (is_prime = rabin_miller(q), is_prime != 0)) {

```


If all three conditions are satisfied we will be given g^b with b a random value 0x40 bytes long.

We will be prompted for g^a and then the server will compute the shared key as g^ab

```c
// function key_exchange@0x00412064
    BCryptGenRandom((BCRYPT_ALG_HANDLE)0x0,nonce,0x40,2);
    …..  
    __gmpz_set_str(b,nonce_hex,0x10);
    __gmpz_powm(g_to_b,g,b,p);
    __gmp_sprintf(local_8c4,&DAT_00418b38,g_to_b);
    thunk_FUN_004124e0("g^b : %s\n",0x3c);
    thunk_FUN_004124e0("input g^a (in hexadecimal, length <= 1000) :\n",g_to_a);

```

### Solution

So we need to find a way to choose g^a so that g^ab mod p = 0x0102030405060708091011121314151617181920212223242526272829303132 

The key insight to solve the challenge is that g^a = b-th root of 0x0102030405060708091011121314151617181920212223242526272829303132 mod p

Now the n-th root of a number modulo m is very easy to compute if it exists, after all, it is how RSA decryption works.

You need to find a number d so that d*n = 1 mod phi(m), then you can just exponentiate a number to the d-th power to get its n-th root

The only thing left to do is to recover b since it is unknown.

The key idea is that we know g^b mod p so b is just the discrete logarithm of this value in base g

Now the discrete logarithm is actually a very difficult problem to solve in general, but in our case, we can make use of three facts:

1. p can be very large (1000 hex digits)
2. b can be small compared to p
3. p - 1 can have many divisors

So mainly thanks to point 2 and 3 we can use *pohlig hellman* algorithm to solve the discrete logarithm.

To do so we repeatedly

1. generate q as a 0x200 bits prime, then we generate several (in my final exploit ~100) small primes 
2. check that p = 2 * q * primes + 1 is prime
Now that we have the correct p and q we can store them to use in the exploit

During the CTF I used
```
P = 0xa9df7c921bd2b3ba34017a30cc7aa17d22a57fb5f5076797e6485529ba0ae8913c1a4eb533e81c0618ec8ad07406bed05ce7ead5562105804047ec68fa2b50ba27914f07401ed0b4f33069d7ff00acf32605931750f2dd358fc59a6a9a8cafcb05b6b37a110f717319eb936f3e7d8b935503499d754f14d3a80114dd04123bdb36bd79a126326819460967d18a7ba987fa4927113afc935d8089696ddbf5e35a2aff1265982b978db0630b1102854abbde6fd2d616bfaf1c3e087ec81fc5e7feb3bad8716fb59085ce7e191ec790c87020fb53dc44085163a612981d8755
Q= 0x15e8976b40fcebcba59bc85604b886744dbccb914611e3b52e0ed4dbb3d38cca9ef62169ce8ce3fed3712eb3245a581a93ae1f61a38d3e41a5549e6c5ce5926829824b22f
```

You can try to factor p to see how nice and small its factors are.

A successful exchange looks like this

```
p (in hexadecimal, length <= 1000) : a9df7c921bd2b3ba34017a30cc7aa17d22a57fb5f5076797e6485529ba0ae8913c1a4eb533e81c0618ec8ad07406bed05ce7ead5562105804047ec68fa2b50ba27914f07401ed0b4f33069d7ff00acf32605931750f2dd358fc59a6a9a8cafcb05b6b37a110f717319eb936f3e7d8b935503499d754f14d3a80114dd04123bdb36bd79a126326819460967d18a7ba987fa4927113afc935d8089696ddbf5e35a2aff1265982b978db0630b1102854abbde6fd2d616bfaf1c3e087ec81fc5e7feb3bad8716fb59085ce7e191ec790c87020fb53dc44085163a612981d8755
q (in hexadecimal, length <= 1000) : 15e8976b40fcebcba59bc85604b886744dbccb914611e3b52e0ed4dbb3d38cca9ef62169ce8ce3fed3712eb3245a581a93ae1f61a38d3e41a5549e6c5ce5926829824b22f
g (in hexadecimal, 0x2 <= g <= 0x40 ) : 11
g^b : 27fb8125b71e4830d06fde55c811077529e410b58dfe884ec6bf23c5b61c9c4bde762ce996ba05162a033810ef67e4922fc18b09ece4e75d3413a12de9f8d3c7f377605f7441500119a149bc0477d816208b3f9d422f6eea68c37475b0e2826e89794139cb3553f5c910366dcd16a6f673e5e2f7f787f9dec05517f62935ce7a5fd52f9b486a9116820c85b36554b695c36fd138d413fe775398ae890af70895b2fad922d75f76becd728af00ffd7ca6cded4e0e2325a578b9ccc89113ec9a904442b1c26ea93794ed810a145c46225c2b74affed832b6d847be5e664524
input g^a (in hexadecimal, length <= 1000) :
67d8fe777cde8cd0895428c60af3b194d9b958260cd4d5983bc127c4355b22482d2fa1346dde1eb2e1494832797f504d2c00aeabc559c63e60372987df8ce1e885835a0592cac48cf6667b4390f6be9fcf15410e1649212dd3d0cfa8862cf3213d3ee090fd7738ab107d24d4c61c0d7e2a63e266d767f5efc4765ef747ff4cf4f29eee28a77e06f7fd7643ffa62c42b7837f2a0ad8a4487ecdbe40e54e4ec48f4f5852211aa7dd5994a58574c72eca43d2003e6354df5a48eec2ec88467334ec4b68f6199174460ac49790c882aecc68497a5f617326b58e6ebfc4f8f197
DH key exchange succeeded!
Key : 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
```

### Difficulties

Reverse engineering cryptographic algorithm can be painful

Debugging on windows if you are not used to is very painful

Following the organizers' hint could prevent you to solve the challenge

At some point before I began to work on the challenge, the organizers posted a hint:
"Pseudo prime"

In my opinion, this hint is very misleading since one can waste a lot of time trying to make the Rabin Miller prime test fail, but it is not needed to solve the challenge.
