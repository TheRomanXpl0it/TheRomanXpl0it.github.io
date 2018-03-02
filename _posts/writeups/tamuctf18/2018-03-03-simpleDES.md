---
layout: post
title: TAMUctf 18 - SimpleDES
categories: ctf_tamuctf18
keywords: crypto
comments: true
authors:
    - daniele-cappuccio
---

```python
import random

def binaryStringToInt(s):
    return int(s[:8], 2)

def charToBinary(c):
    return bin(ord(c))[2:].zfill(8)

def stringToBinary(s):
    r = ''
    for c in s:
        r += charToBinary(c)
    return r

def XORBinaryStrings(a, b):
    r = ''
    l = min(len(a), len(b))
    for i in range(l):
        r += str(int(a[i]) ^ int(b[i]))
    return r

def divideIntoBlocks(s, N):
    r = []
    while len(s) > 0:
        r.append(s[:N])
        s = s[N:]
    return r

def createSBoxS1():    
    d = {}   
    d['0000'] = '101'
    d['0001'] = '010'
    d['0010'] = '001'
    d['0011'] = '110'
    d['0100'] = '011'
    d['0101'] = '100'
    d['0110'] = '111'
    d['0111'] = '000'
    d['1000'] = '001'
    d['1001'] = '100'
    d['1010'] = '110'
    d['1011'] = '010'
    d['1100'] = '000'
    d['1101'] = '111'
    d['1110'] = '101'
    d['1111'] = '011'
    return d

def createSBoxS2():   
    d = {}  
    d['0000'] = '100'
    d['0001'] = '000'
    d['0010'] = '110'
    d['0011'] = '101'
    d['0100'] = '111'
    d['0101'] = '001'
    d['0110'] = '011'
    d['0111'] = '010'
    d['1000'] = '101'
    d['1001'] = '011'
    d['1010'] = '000'
    d['1011'] = '111'
    d['1100'] = '110'
    d['1101'] = '010'
    d['1110'] = '001'
    d['1111'] = '100'
    return d

def generateRandomString(length):
    r = ''
    for i in range(length):
	c = random.randint(0, 255)
	r += chr(c)
    return r

def simpleDES(R, binKey, plaintext):

    # Methods to create our S-boxes
    d1 = createSBoxS1()
    d2 = createSBoxS2()
    cyphertext = ''
    
    # Let's use a list of chars instead of a string
    binaryKey = list(binKey)

    # Divide into blocks
    tmp = stringToBinary(plaintext)
    blocks = divideIntoBlocks(tmp, 12)

    for i in range(len(blocks)):
        block = blocks[i]
        Lr, Rr = block[:6], block[6:]
        for r in range(R):
            # Remapping values of Rr
            Rr_remap = Rr[:2] + Rr[3:4] + Rr[2:3] + Rr[3:4] + Rr[2:3] + Rr[4:]
            # XOR the result with 8 bits of key beginning with key[i*R+r]
            index = i*R+r
            xorLeft = 8
            x = ''
            while xorLeft > 0:
		tmp = str(int(binaryKey[index]) ^ int(Rr_remap[8-xorLeft]))
		x += tmp
		index += 1
		index %= len(binaryKey)
		xorLeft -= 1
            # Divide the result into 2 4-bit sections S1, S2
            S1, S2 = x[:4], x[4:8]
            # Concatenate the result of the S-boxes
            v = d1[S1] + d2[S2]
            # XOR the result with Lr
            Lr_xored = XORBinaryStrings(Lr, v)
            cyphertext += Lr_xored
            Lr = Rr
            Rr = Lr_xored

    return cyphertext
    
R = 2
key = 'Mu'
binaryKey = stringToBinary(key)
cypher = '011001010010001010001100010110000001000110000101'
 
i = 0
flag = 'Gigem{'
b = ''
while True:
    s = generateRandomString(6)
    binaryS = stringToBinary(s)
    r = simpleDES(R, binaryKey, s)
    if r[i:i+12] == cypher[i:i+12]:
	b += binaryS[i:i+12]
	i += 12
    if i == 48:
	# Finished
	break

while len(b) > 0:
    flag += chr(binaryStringToInt(b))
    b = b[8:]
print flag + '}'
```

This prints out our flag:
```Gigem{M1N0N!}```
