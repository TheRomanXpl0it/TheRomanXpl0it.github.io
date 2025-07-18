---
title: Codeblue CTF 2017 - Common Modulus 2
date: '2017-11-10'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- ctf_codeblue2017
- writeup
- codeblue2017
tags:
- number
- theory
- crypto
- rsa
authors:
- chq-matteo
---

<script type="text/javascript" async
  src="https://cdn.rawgit.com/mathjax/MathJax/2.7.1/MathJax.js?config=TeX-MML-AM_CHTML">
</script>
<script type="text/x-mathjax-config">
MathJax.Hub.Config({
  TeX: { equationNumbers: { autoNumber: "AMS" } },
  tex2jax: {
    inlineMath: [['$','$'], ['\\(','\\)']],
    processEscapes: true
  }
});
</script>
Next in the series [Common Modulus 3](../common3)

If you haven't already, check out [Common Modulus 1 Writeup](../common1)!

We have solved [Common Modulus 1](../common1), but now there's more!

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
