---
title: Codeblue CTF 2017 - Common Modulus 2
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

Next in the series [Common Modulus 3]({{< ref "posts/codeblue-ctf-2017-common-modulus-3/index.md" >}})

We have solved [Common Modulus 1]({{< ref "posts/codeblue-ctf-2017-common-modulus-1/index.md" >}}), but now there's more!

```python
e = 3 * get_random_prime(20)
```

Mmmmh now $MCD(e_1, e_2) = 3 \ne 1$ so we can't get the flag as easily.

That is because the $x$ and $y$ we find with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) will be so that $xe_1 + ye_2 = 3$ (again thanks to the [Bézout's identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity)).
What we get is $m^3 \mod N$, still not that bad.

We notice that $m^3$ is quite smaller than $N$ and also that the flag is surely shorter that 2048/3 = 682 bits roughly 85 characters.

We can actually take the cube root of $m^3$ and recover the flag!

## Solution SageMath script
```python
from binascii import unhexlify
import string
def solve(e1, e2, n, m1, m2):
    d, x, y = xgcd(e1, e2)
    c = (pow(m1, x, n) * pow(m2, y, n)) % n
    print unhexlify(hex(long(pow(long(c), 1/3)))[2:-1])
```
