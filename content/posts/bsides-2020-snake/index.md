---
title: BSIDES 2020 - Snake
date: '2020-06-13T15:08:35+02:00'
math: false
categories:
- writeup
tags:
- reverse
- webasm
authors:
- Capo80
---

This was a very interesting challenge and also the first time i reversed a web assembly binary.

## Info

Points: 400

Description:


It is not a classic Snake game... Something is different.. Did you see it?! Do you think it is random? Well, think again:)


## The Snake Bot

The site of the challenge has a simple snake game implemented in JavaScript and WebAsm.

The description of the challenge teels us to look at the differences with the traditional snake game, the only difference is that there are two different types of fruit.

Also, the order of the fruits stays the same, this suggests that the flag is encoded as binary sequence of theese fruits, in fact:

```
*  *        
 **         <--- this is a 0
 **
*  * 

 **
 **          <--- this is a 1
*  *
*  * 
```
So, the first idea, without even looking at the wasm, was to create a snake bot to recover the sequence of the fruits, the result was very entertaining to whatch:

<img src="/bsides2020/snake.gif" alt="snake"/>

But unfortunately the sequence that we extracted was garbage:
```
BSidesU.Ñ9QÄ%6.FW5Y]..Ð..
```
Still the start of the string is correct which means we are on the right track, i guess we actually need to reverse the wasm.

## Time to reverse

By placing a bunch of breakpoints in the code we find out that the function that checks if the snake is on the fruit is ***func15*** and by looking at it we can see that the value of the fruit is decided here, by calling ***func7***:

```
      local.get 36
      local.get 35
      i32.store offset=1116
      call 7                  <--------------------- call function 7 for the value of the fruit
      local.set 37
      i32.const 0
      local.set 38
      local.get 38
      local.get 37
      i32.store offset=1112         <-------- save the value returned in memory to pass it to the front end later
      i32.const 0
      local.set 39
      local.get 39
```

Looking at function 7 it is filled with the logic to trasform an integer to the corresponding binary, but it also has this block that is called every 8 fruits, in fact this block is used to generate a new number/letter for the flag, if we can reverse this we have the flag:
```
    block  ;; label = @1
      
      ------------------------------------------------------
      local.get 7                 <--- activates every 8 fruits
      br_if 0 (;@1;)
      ------------------------------------------------------
      
      i32.const 0
      local.set 8                 <---- takes a value A from memory (this is actually the value of the previus number)
      local.get 8
      i32.load8_u offset=1132
      
      ------------------------------------------------------
      
      local.set 9
      i32.const 24
      local.set 10
      local.get 9             
      local.get 10              <-----  some clean up on A
      i32.shl
      local.set 11
      local.get 11
      local.get 10
      i32.shr_s
      local.set 12
      
      ---------------------------------------------------------
      local.get 2
      i32.load offset=8          <------- Takes value B from memory (This is actually the count of how many fruits have been eaten % 56 )
      local.set 13
      i32.const 8
      local.set 14
      local.get 13
      local.get 14
      i32.div_s                  <------- Divides by 8 to obtain the number of letters generated until now
      local.set 15
      local.get 15
      i32.load8_u offset=1024    <------- Uses value B as and index to retrieve value C from the vector stored at this location (C = vect[B])
      local.set 16
      i32.const 255
      local.set 17
      local.get 16
      local.get 17
      i32.and                    <------- Some clean up on C
      ------------------------------------------------------------
 
      local.set 18
      local.get 12
      local.get 18
      i32.xor                   <----- takes the last number generated and does the xor with the value of the vector ( A ^ C )
      local.set 19
      i32.const 0
      local.set 20
      local.get 20
      local.get 19
      i32.store8 offset=1132    <----- saves the result of the vectors to generate the next 8 fruits
    end
```

After this we just need the starting value of the offset 1132 which we can find in the ***game_init*** function:

```
    i32.const 115
    set_local $var3
    
    .
    .
    .
    
    i32.const 0
    set_local $var50
    get_local $var50
    get_local $var3
    i32.store8 offset=1132
```

The starting value is 115, with this i recreated the code in python and obtained the values generated by the game, the result is:

```
BSidesTetNCBTsBSidesTetNCBTsBSidesTetNCBTsBSidesTetNCB
```

Which is still not the flag and is also different from what the Snake Bot returns (for some reason?).

But where is the flag? Well, if we look at the memory where the vector for the xor is located we can see that is actually a lot longer than required, in fact it is:

```
[49, 17, 58, 13, 1, 22, 39, 24, 26, 100, 2, 2, 2, 75, 44, 102, 66, 23, 11, 2, 50, 54, 92, 106, 48, 1, 2, 21, 38, 47, 63, 60, 70, 80, 22, 0, 64, 87, 59, 61, 27, 38, 43, 28, 91, 108, 51, 95, 7, 70, 28, 11, 1, 25]
```

Seeing this i tried the same xoring algorithm with the whole vector:

```
for i in range(0, len(xor_values)):
	start = start^xor_values[i]
	flag += chr(start)
```

And this gave me the flag:

```
BSidesTLV2020{W1sdom_i5_only_pOs5ess3d_by_th3_l34rned}
```



