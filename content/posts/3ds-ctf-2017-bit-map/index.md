---
title: 3DS CTF 2017 - Bit Map
date: '2017-12-19'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- writeup
- 3ds2017
tags:
- forensics
- steganography
- html
- python
authors:
- daniele-cappuccio
---

```python
from __future__ import print_function
from bs4 import BeautifulSoup

with open('index.html', 'r') as f:
    html = f.read()

soup = BeautifulSoup(html, 'html.parser')

tmp = []

for e in soup.find_all('td'):
    tmp.append(e.get('bgcolor'))

r = ""
for bg in tmp:
    r = r + bg[1:].decode('hex')

if '3DS' in r:
    idx = r.index('3DS')
    while not r[idx] == '}':
        print(r[idx], end='')
        idx = idx + 1
    print('}')
```

This script prints our flag -> `3DS{H1dd3n_1n_7ru3_C0l0r5}`
