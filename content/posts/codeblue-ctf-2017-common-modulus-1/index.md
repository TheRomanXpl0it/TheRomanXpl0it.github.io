---
title: Codeblue CTF 2017 - Common Modulus 1
date: '2017-11-10'
lastmod: '2019-04-07T13:46:27+02:00'
math: true
categories:
- writeup
- codeblue2017
tags:
- crypto
- number-theory
- rsa
authors:
- chq-matteo
---

Next in the series [Common Modulus 2]({{< ref "posts/codeblue-ctf-2017-common-modulus-2/index.md" >}})

Quick summary of RSA
$cipher text = message^e \mod N$

We have a message (the flag) encrypted with the same $N$, but with two different $e$.
As the name suggests the solution to this problem is a [common modulus attack](https://crypto.stackexchange.com/questions/16283/how-to-use-common-modulus-attack)

The idea of the attack is that if we know
1. $m^{e_1} \mod N$
2. $m^{e_2} \mod N$
3. $MCD(e_1, e_2) = 1$

then we can recover $m$.

Luckily $e_1$ and $e_2$ and two random generated primes so it is very likely that (3) holds and we have (1) (2) because we have the two cipher texts.

## Explanation of the attack
The [Bézout's identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity) guarantees that we can find with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) $x$ and $y$ so that $xe_1 + ye_2 = 1$.
We can use this fact to compute $m$.

We are given the cipher texts $c_1 = m^{e_1} \mod N$ and $c_2 = m^{e_2} \mod N$

If we raise $c_1$ to the $x-th$ power modulo $N$ we get $c_1^{x} = (m^{e_1})^{x} = m^{xe_1} \mod N$ similary with $c_2$ and $y$ we get $c_2^{y} = m^{ye_2} \mod N$

If we multiply them we get $m^{xe_1}m^{ye_2} = m^{xe_1 + ye_2} \mod N$, but we have proven that the exponent is actually equal to $1$!
So what we really get is $m$!

---

Note: One of $x$ and $y$ will be negative

## Solution SageMath script
```python
from binascii import unhexlify
def solve(e1, e2, n, c1, c2):
    d, x, y = xgcd(e1, e2)
    m = (pow(c1, x, n) * pow(c2, y, n)) % n
    print unhexlify(hex(long(m))[2:-1])
```
