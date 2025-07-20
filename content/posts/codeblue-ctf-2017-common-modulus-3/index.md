---
title: Codeblue CTF 2017 - Common Modulus 3
date: '2017-11-10'
lastmod: '2019-04-07T13:46:27+02:00'
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

We have solved [Common Modulus 1]({{< ref "posts/codeblue-ctf-2017-common-modulus-1/index.md" >}}) and
[Common Modulus 2]({{< ref "posts/codeblue-ctf-2017-common-modulus-2/index.md" >}}), but now there's even more!

Bigger public exponent? Check
```python
e = 17 * get_random_prime(20)
```

Padding? Check
```python
while len(flag) * 4 < 8192:
  flag += '00'

FLAG = long(flag[:-2], 16)
```

Proper padding? Luckily not!

We have to:
1. Remove the padding
2. take the seventeen-th root of the message (at least hope we can)

The bigger public modulus let's us hope for the best ($8192 / 17 = 481$ bits or circa 60 bytes).

Since `flag` is parsed as a base 16 integer the `00` padding is just a multiplication by $2^4$. We don't know how many `00` of padding there are, but we know that it is more than 0 and less that 8192/4 so we can happily brute force that!

Remember that multiplication for $2^{-4} \mod N$ is actually just like dividing by $2^{4} \mod N$ or cancelling a `00`
```python
for i in range(0, 2048):
    try:
        m17unpadded = (m17padded * pow(2, -17*4*i, n)) % n
    ...
```

Then we try to take the 17-th root
```python
m, _ = ZZ(m17unpadded).nth_root(d, truncate_mode=1)
```

And check for a known plaintext like `CBCTF`
```python
flag = unhexlify(hex(long(m))[2:].replace('L', ''))
    if 'CBCTF{' in flag:
        print flag
        break
```

I did mess up a couple of times during the competition, but in the end we got the flag.

_______
N.B.
I renamed a couple of variables and didn't test the code again

## Solution SageMath script

```python
from binascii import unhexlify
import string
def solve(e1, e2, n, c1, c2):
    d, x, y = xgcd(e1, e2)
    print d
    m17padded = (pow(c1, x, n) * pow(c2, y, n)) % n # (flag * 2**x)**17 = flag ** 17 * 2**17x
    for i in range(0, 2048):
        try:
            m17unpadded, _ = ZZ(m17padded * pow(2, -d*4*i, n)).nth_root(d, truncate_mode=1)
            flag = unhexlify(hex(long(m17unpadded))[2:].replace('L', ''))
            if 'CBCTF{' in flag:
                print flag
                break
        except TypeError as e:
            # debugging debugging debugging
            print e
            print long(m17unpadded)
            pass
```
