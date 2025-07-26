---
title: GPN 2024 - Parabox
date: '2024-06-13T15:08:35+02:00'
math: false
categories:
- writeup
tags:
- reverse
- retro
- gba
authors:
- Capo80
---

WARNING! The second video in the "Find the Missing -> UNDO for the win" Section and the video in "Conclusions" contains flashing images, it should not auto play but pay attention.

## Challenge Information 

### Description

<div style="text-align: center;">
    <img src="/gpn2024/images/cover.png" alt="drawing" width="200"/>
</div>

[This game](https://www.patricksparabox.com/) looked real fun, unfortunately they did not support my platform. I wanted to play it anyway, so I built this small version myself. Some things went wrong (writing assembly is hard), but I'm sure you can win nonetheless.

Go push some paraboxes!


### Category

Reverse, Hard

### Files

- parabox.tar.gz, contains gbc ROM file and GearBoy, which is a linux Game Boy Color emulator

### TLDR

Challenge is a Game Boy Color ROM containing a version of the Parabox game, objective is to win the game on the server by sending the correct moves. The objecctive of the game is to position some boxes and the player in the corrrect positions, for each level we can traverse 3 maps, the main screen plus 2 paraboxes which we can enter, one blue, one green. There are a total of 8 levels and some are impossible trough normal playing, but with some reversing i was able to find 3 vulnerabilities that can be used to beat the game.

The 3 vulns are:
- The game saves a list of moves, we can overflow this list by 1 simply by playing the game and overwrite the position of the victory square which is saved immediatly after, can be used to beat the "Impossible" level which has an unreachable finish;
- To implemented the undo feature the game periodically saves a copy of each map, when redo is pressed the copy is restored and the moves are replayed, if a level has less maps of its predecessor when we undo we will copy in an additional map from it overwriting some memory, this can be used on the "Missing" level which has impossible constraints;
- In the "Last Hurdle" boxes have a connection where they should not;

An overall interesting challenge which included both reversing and some very easy pwning.

## WriteUp

### Getting things going

I started late for this CTF and when i joined my team i found out we had some new team members which were on their way to solve the easier challenges, so i left them to their devices and decided that i would straight to the hardest ones.

After immediately deciding that "provably wrong" was not for me i landed on Parabox, a retro game reverse challenge, which i generally enjoy.

In the zip provided we find their complete server setup with a Dockerfile and a README which explains that we need to reverse the "parabox.gbc" ROM file and that our objective which is simply to "win the game".

Let's start by looking at how the docker sets up the challenge, it clones a version of [GearBoy](https://github.com/drhelius/Gearboy), which is a GameBoy Color emulator and applies a patch to turn off the graphic component, automatically apply the inputs from the player and check whatever the user has achieved the win condition after it.

First thing i did was patch back in the graphic component so that i can actually see the game and reactivate the event monitor so that i could provide inputs from the keyboards after the initial array has run out. Thankfully the organizers left all the removed code as comments so the only thing i needed to do was uncomment some lines and add a check to prevent the game from exiting after it finishes the inputs.

The first levels are just an introduction to the game, so i installed [LogKeys](https://github.com/kernc/logkeys) to record my keyboard while i solved each screen and wrote a small python script to encode the moves in the game format, here is the solutions of the first 5 levels:

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_0.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video> 
<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_1.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>
<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_2.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>
<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_3.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>
<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_4.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>

The objective of the game is to get our character in the finish square and to put a box in all the designed spots, the twist here is the presence of "paraboxes" which are boxes that we both move and enter inside, as shown in level 4.

After completing the intro levels the real challenge starts, we reach the "Impossible" level which, as the name suggests, has an unreachable ending square and is thus impossible to finish through normal means. Well, i had my fun with the game, now it's time to break it.

### Beating the "Impossible"

The solution to this part is actually pretty easy, i passed the level by accident a couple times and then i noticed what was happening by looking at the program memory, which is thankfully one of the features offered by GearBoy.

Let's note down some of the area in memory to look up later, i was able to find:
- the map of the level at ```0xc100```, red box;
- the current position of the player at ```0xc1f8```, blue box;
- the history of played moves at ```0xc200```, green box;
- the position of the winning square at ```0xc271```, yellow box;

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/memory.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>

Any pwn expert reading this has already snuffed out where a vulnerability might be, i am not very good at pwning so it took me a bit of time but the interesting part here is that we have an array that grows, the move history, which is very near our victory square position, if the boundary of this array is not enforced correctly we may be able to overwrite the position of the finish.

Indeed, this is a vulnerability as the limit of the move history is one byte too much, allowing us to overwrite the position with the value assigned to our move. Again from the move history we find out that the values are:
- ```0x10``` for RIGHT;
- ```0x20``` for LEFT;
- ```0x40``` for UP;
- ```0x80``` for DOWN;

Now all we need to do to beat the impossible level is make a bunch of random moves to fill up the history array until the end, then make a move which corresponds to a square we can reach, which is only LEFT, then go to that square and finish the level. Using left as our overflow move we end up with the finish in the bottom left, here's my version of the solution:

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_5.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>



After beating this we reach level "small" which is a normal level, then we reach "Missing" and even after putting all the boxes in the correct place the level wont let me advance, clearly there some shenanigans happening here and it's actually time to start reversing to find out what is going on.

### Find the "Missing"

With the initial googling for this challenge i discovered [GhidraBoy](https://github.com/Gekkio/GhidraBoy) which is a Ghidra extension for reversing GBC games, so installed that, booted up Ghidra and the result was some really nicely formatted pseudo-code which was pretty surprising.

#### Understanding victory conditions


With a decompiler in hand i put some memory breakpoints with GearBoy on the address of the finish square, i wanted to check how a victory is calculated as it seems that this was the problem with the level. Turns out that the victory condition is checked at every game loop by the function at ```0x0733```, and after some reversing i discovered that it does something like this:

```c
struct victory_condition {
    u8 position;
    u8 map;
    u8 value;
};
u8 check_victory() {
  struct victory_condition* curr = 0xc279; // victory condition position
  u8 win = 1;
  u8 curr_value;
  while( true ) {
    if (curr->position == -1) break;
    curr_value = get_value_from_map(curr->map, curr->position);
    if (!check_correct_value(curr->value, curr_value)) {
      win = 0;
    }
    victory_condition++;
  }
  return win;
}
```

There are multiple conditions starting at ```0xc279``` that we need to beat a level, the first is always to have the player on the finish square, then we can have an arbitrary number of other conditions which check the correct position of the boxes. Each condition is associated with a map, a level can have up to three maps, the first is where the players spawns, the other two are the green and blue "paraboxes", shown below for the level "small":


<img src="/gpn2024/images/small_1.jpeg" alt="drawing" width="250"/>
<img src="/gpn2024/images/small_2.jpeg" alt="drawing" width="250"/>
<img src="/gpn2024/images/small_3.jpeg" alt="drawing" width="250"/>

Now let's have a look at the victory conditions for the "Missing" level:
```c
{
    [0x06, 0, 0],
    [0x24, 1, 1],
    [0x25, 1, 1],
    [0x25, 1, 1],
    [0x04, 2, 1],
    [0x07, 2, 1],
}
```

Unfortunately, it looks like we have two extra conditions on map 2, the green box, which we can't access in the "Missing" level, making the level impossible.

Here i got stuck for a while, then i tried pressing a button which i still hadn't used, the "UNDO", and discovered something interesting.

#### UNDO for the win

The game offers an UNDO button for when you make a mistake during the puzzle, this allows to cancel your last move, this is probably why the move history exists, to allow for the rewind.

However, the implementation of the feature is peculiar, instead inverting the logic of a single move to rewind, it restores all the maps of the level to a past state, then it re-plays all the moves in the history except for the last one, it is not shown on screen but we can clearly see it from the memory if we slowdown the video a bit:

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/undo.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>

Now after a bit of reversing and some breakpoints i was able to find the functions that save and restore the level, which are at ```0x06c3``` and ```0x0706``` respectively. Here we can find the vulnerability, when a level is saved, only the maps active in the level are copied to the buffer, but when a level is restored, all 3 maps are replaced with the contents of the buffer, even if the current level does not utilize all the maps. Now, if we remember the victory conditions for the "Missing" level, we needed a 2 objects in map 3 which is not present in the level, luckily for us, the level before, "Small", has a green parabox, which corresponds to map 3. What we need to do is make a bunch of moves in the level "Small" to make the game save its state, then in the level "Missing" we undo to copy "Small" third map into "Missing".

Now, the only thing left to do is setup the state of the green parabox in "Small" so that it satisfies the win conditions of "Missing" before saving the state, this means we need to fill up both spots in the parabox, unfortunately, this is impossible as the level has only one box we can use. However, after a bit of testing, it turns out that the id representing the player on the map changes at every level depending on the number of boxes and the value assigned to us by the level "Small" actually fulfils the requirements for a box in the level "Missing".

So now we have all the pieces, we go in and out of the green box in "Small" to setup a saved state for map 3, then in "Missing" we press UNDO at the start to get the last winning conditions, then complete the level as normal. Here is my solution:

BEWARE! FLASHING IMAGES!

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_6_7.mp4"  type="video/mp4">
    your browser does not support the video tag.
</video> 

I skipped some details for the sake of clarity, but the game actually saves 4 states to restore instead of only 1, it does so every 32 moves probably because it would take too much time to re-play the full length of the move history array, so at the start of "Missing" i have to waste some moves to re-align myself with the correct saved state.

Also in both levels i end up overwriting the finish square with a bad move, so at the end i have to reset it to a reachable square, could have optimized it better but i was starting to get real tired at this point so i just left it.

### A bit of luck saves the night

So i reached this point, the "Last Hurdle", at 4AM in the morning, i started this challenge at 7PM after a full 8-hour work day and skipped dinner, so i was pretty much about to collapse.

I really wanted to finish this challenge to get the first blood before going to bed, but i had to hope for an easy last level or i would not make it. This is what is saw:

<img src="/gpn2024/images/last_1.jpeg" alt="drawing" width="250"/>
<img src="/gpn2024/images/last_2.jpeg" alt="drawing" width="250"/>
<img src="/gpn2024/images/last_3.jpeg" alt="drawing" width="250"/>

There is no hidden condition here so you just need to get the box at the center of the green parabox and you win, unfortunately there is no way for the player to enter the green parabox, i edited the game memory removing a wall to see it the first time, so you can never push the box down to its position.

My idea here was to somehow duplicate the boxes and push both inside the green parabox so that one would go in the correct square and, in a wonderful moment of luck, i pushed to box down in the bottom left corner of the blue parabox.

The bottom and right side of the blue parabox are facing a wall so i should not able to push anything in, i followed the box and, surprisingly, i found myself inside the green parabox. By sheer luck, in only around 20 minutes of playing around, i found the glitch, the left corner of the blue parabox is connected to the green parabox, with this information the solution to the level is trivial, here it is:

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/level_8.mp4"  type="video/mp4">
    your browser does not support the video tag.
</video> 

## Conclusions

With all the solutions i updated my script to send the moves to the server with pwntools and i got the flag:

```
GPNCTF{p41n_70_d3v3l0p_h0p3fully_l355_p41n_70_50lv3_fd29a4b2833}
```

I can imagine the pain to develop, thank you for your sacrifice, i had fun, not sure if it was less of a pain tough.

I got my first blood and i went to sleep at around 5AM pretty happy with myself, i was a bit less happy when i discovered i was the only solve for the challenge and i could have just gone to sleep at a normal time.

This thing got pretty long and i could not even include my fuzzing experiments with the challenge, congrats if you made down here, here is the full video of the solve:


BEWARE! FLASHING IMAGES!

<video width="320" height="240" controls>
  <source src="/gpn2024/videos/full_solve.mp4"  type="video/mp4">
    your browser does not support the video tag.
</video> 

## Tools used

- Ghidra with [GhidraBoy](https://github.com/Gekkio/GhidraBoy), used as a dissassembler and decompiler, the extension produced some very readable code which helped me greatly with the challenge;

- [GearBoy](https://github.com/drhelius/Gearboy), used as an emulator and debugger, it was already included in the challenge and the debugger offers all functionalities needed during reversing;

- [LogKeys](https://github.com/kernc/logkeys), linux keylogger which i used to extract the moves i played on the more straightforward levels
