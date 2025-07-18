---
title: backdoorctf 2017 - NoCalm Writeup
date: '2017-09-24'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- ctf_backdoorctf17
- writeup
- backdoorctf17
tags:
- reverse
authors:
- andreafioraldi
---

<img class="img-responsive" src="{{ site-url }}/assets/backdoorctf17/nocalm-1.png" alt="Screenshot of decompiled main() function checking flag length and conditions" width="603" height="235">

Decompiling the main function we see that each byte of the flag must be passed as argument to the program.

The number of arguments must be 31, as we can see from the first if statement.

The program check the correctness of the flag with a series of nested ifs and arithmetic stuffs.

If the flag is correct, it calls the success function, else it calls fail.

<img class="img-responsive" src="{{ site-url }}/assets/backdoorctf17/nocalm-2.png" alt="Screenshot of decompiled code checking for success() or fail() functions" width="306" height="177">

Using [angr](http://angr.io/) we can obtain the correct flag effortlessly.

```python
import angr
import claripy
import simuvex
import resource
import time

proj = angr.Project('challenge', load_options={'auto_load_libs' : False})

fail = 0x004007CC
success = 0x004007B6

start = 0x004007E2
avoid = [fail]
end = [success]

argv = []
for i in xrange(31):
    arg = claripy.BVS("input_string" + str(i), 8)
    argv.append(arg)

state = proj.factory.entry_state(args=argv, remove_options={simuvex.o.LAZY_SOLVES,})

pg = proj.factory.path_group(state, veritesting=False)

start_time = time.time()
while len(pg.active) > 0:

    print pg

    pg.explore(avoid=avoid, find=end, n=1)

    if len(pg.found) > 0:
        print
        print "Reached the target"
        print pg
        state = pg.found[0].state
        
        flag = ""
        for a in argv:
            flag += state.se.any_str(a)[0]
        print "FLAG: " + flag
        break

print
print "Memory usage: " + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"
print "Elapsed time: " + str(time.time() - start_time)
```
