---
layout: post
title: SharifCTF 8 - Fifteen puzzle
categories: ctf_sharifctf18
keywords: "algorithm"
comments: true
authors:
    - dp1
---
{{ page.date | date: "%B %-d, %Y" }}

> You are given 128 puzzles (https://en.wikipedia.org/wiki/15_puzzle)
> The ith puzzle determines the ith bit of the flag:
> 1 if the puzzle is soluble
> 0 if the puzzle is unsoluble
> Implement is_soluble() below, and use the code to get the flag!

This was an easy task, as all that was required was determining if a given 15-puzzle was solvable. After some thirty seconds of googling, I had the algorithm, as described [here](https://www.geeksforgeeks.org/check-instance-15-puzzle-solvable/). All we have to do is calculate the inversion count of the numbers and we're basically done.
Here is the code I used, with the naive `O(N^2)` algorithm for the inversion count:

---
{% raw %}
```python
data = """
[...]
""".split('\n')

def invcount(data):
    res = 0
    for i in range(len(data)):
        for j in range(i):
            if data[j] > data[i]:
                res += 1
    return res

out = ''

for i in range(128):
    mat = []
    row = -1 # empty cell's row
    for j in range(4):
        while not data[0].strip().startswith('|'):
            data = data[1:]
        line = data[0].split('|')[1:-1]
        if '  ' in line:
            row = j
        mat += [int(x, 10) for x in line if len(x.strip()) > 0]
        data = data[1:]
    
    if (row + invcount(mat)) % 2 == 0:
        out = '1' + out
    else:
        out = '0' + out

print('SharifCTF{%016x}' % int(out, 2))
```
{% endraw %}

```bash
SharifCTF{52d3b36b2167d2076b06d8101582b7af}
```
