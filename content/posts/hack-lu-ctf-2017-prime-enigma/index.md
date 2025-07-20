---
title: Hack.lu CTF 2017 - Prime Enigma
date: '2017-10-19'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- hacklu17
tags:
- crypto
- number-theory
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

We have

\begin{equation}
    B = g^d \mod p
    \label{eq:b}
\end{equation}

\begin{equation}
    k = A^d \mod p
    \label{eq:k}
\end{equation}

\begin{equation}
    c = k m \mod p
    \label{eq:c}
\end{equation}

We know $B$, $g$, $p$, $A$ and $c$ and we want to recover $m$.

The only unknown in \eqref{eq:b} is $d$.
Luckily $B = g^d \equiv p-1 \equiv -1 \mod p$
So $(g^d)^2 \equiv 1 \mod p$

We also know that $g^{p-1} \equiv 1 \mod p$
So dividing repeatedly $p-1$ by $2$ we will get some $d'$ such that $g^{d'} \equiv -1 \mod p$

Well $d = \frac{p-1}{2}$.

We can compute easily $k$ (we now know $A$, $d$ and $p$).
We compute his modular multiplicative inverse modulo $p$ and multiply that with $c$ to get $m$.

-----------

### Challenge
```python
from secret import flag, key

f = open('ciphertext.txt', 'w')

p = ...
g = 5
A = ...
d = key
m = int(flag.encode('hex'), 16) % p

B = pow(g, d, p)
k = pow(A, d, p)
c = k * m % p

f.write(str(B) + '\n')
f.write(str(c) + '\n')

f.close()
```
