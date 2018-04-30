---
layout: post
title: The most boring
categories: ctf_asisquals18
keywords: "ppc bruijn"
comments: true
authors:
    - dp1
---
{{ page.date | date: "%B %-d, %Y" }}

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

<pre>
*******************************************************************************
| hi all, welcome to the most Boring task, but I think its interesting for all|
| Think about a rotating drum, each of the segments is of one of three types, |
| such that any k consecutive segments uniquely determine the position of the |
| drum, example: for k = 3, the circular sequence 111220120210110200100022212 |
| has desired property. In each stage, send us three distinct sequences with  |
| given k, and get the valuable flag :))                                      |
*******************************************************************************
</pre>

Easy, right? Probably the hardest part was understanding the question. While it doesn't say it explicitly, the sequences needed to contain all possible subsequences of length `k`. This means that they had to be [de Bruijn sequences](https://en.wikipedia.org/wiki/De_Bruijn_sequence). Luckily the Wikipedia page also contains python code to generate those sequences, so by just writing a small wrapper around it I got to the flag.
The only missing part was how to generate three different sequences, but it was enough to swap che characters around for them to be different (e.g. `001122` -> `110022`)

---

```python
import itertools, hashlib, sys
from pwn import *

def bruijn(k, n):
	alphabet = list(map(str, range(k)))

	a = [0] * k * n
	sequence = []

	def db(t, p):
		if t > n:
			if n % p == 0:
				sequence.extend(a[1:p + 1])
		else:
			a[t] = a[t - p]
			db(t + 1, p)
			for j in range(a[t - p] + 1, k):
				a[t] = j
				db(t + 1, t)
	db(1, 1)
	return "".join(alphabet[i] for i in sequence)

def captcha(target):
	target = target.strip().split(' ')[-1]
	print '[+] Solving captcha for', target
	alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	for a,b,c,d,e in itertools.product(alpha, repeat=5):
		if hashlib.sha256(a+b+c+d+e).hexdigest()[-6:] == target:
			return a+b+c+d+e
	print "[!] Captcha unsolved"
	quit()

def solve(line, r):
	k = int(line.strip().split(' ')[-1])
	print '[+] Solving for k =', k
	sol = bruijn(3, k)
	r.recvuntil('first sequence:')
	r.sendline(sol)
	r.recvuntil('second sequence:')
	sol = sol.replace('0', 'a').replace('1', '0').replace('a', '1')
	r.sendline(sol)
	r.recvuntil('third sequence:')
	sol = sol.replace('0', 'a').replace('2', '0').replace('a', '2')
	r.sendline(sol)

r = remote('37.139.22.174', 56653)

s = r.readline()
while not s.startswith('Submit'):
	s = r.readline()
r.sendline(captcha(s))

while True:
	s = r.readline()
	solve(s, r)
	s = r.readline()
	while len(s.strip()) == 0:
		s = r.readline()
	if 'ASIS' in s:
		print s
		break

```

```bash
(pwn) dario@PC:~/desktop/ctf/asisquals2018/boring$ python t.py
[+] Opening connection to 37.139.22.174 on port 56653: Done
[+] Solving captcha for c18349
[+] Solving for k = 3
[+] Solving for k = 4
[+] Solving for k = 5
[+] Solving for k = 6
[+] Solving for k = 7
[+] Solving for k = 8
[+] Solving for k = 9
Congratz! :) You got the flag: ASIS{67f99742bdf354228572fca52012287c}

[*] Closed connection to 37.139.22.174 port 56653
```
