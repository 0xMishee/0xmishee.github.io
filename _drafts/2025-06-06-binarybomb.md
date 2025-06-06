---
title: "The Binary Bomb"
date: 2023-12-30 15:30:00 +0200  
categories: [SysInternals]
tags: [sysinternals, windows]
description: Solution walkthrough to the binary bomb excercise.
comments: false
---

Just recently decided that I was done with Arch1001, after going through one and a half time, over at OST2 which is taught by Xeno. But couldn’t put it aside before I tried and finish the last challenge, the binary bomb!

Arch1001 x86–64 Assembly : Course | Arch1001 | OpenSecurityTraining2 (ost2.fyi)

So lets just jump into the PE and see what lurks within…

Straight out the gate is the main function which looks to take some arguments. We see that the RDI and RBP are saved; which is done by the callee. These are later poped at .text:0000000140011BB9 and .text:0000000140011BBA; such balance. It adds some space through sub and looks to zero out/fill some buffer with rep stosd. The binary is compiled with Visual Studio which we can see by identifying “JustMyCode”/JMC option.


After getting to the conditional jump at .text:0000000140011A10 it checks the number of arguments. If they’re zero it just falls through and jumps to the main part of main. If not, it jumps over to .text:0000000140011A26 where it will try to load our file. If it does so successfully it will traverse to main:loc_140011AA0 else it will print a message ”%s: Error: Couldn’t open %s\n”.


I knew there were six phase/stages to this binary. Which is quite easily seen here together with all the strings that gets printed. It seems to follow the same pattern throughout the binary.

Print some string.
Call function that either reads the commandline or from a textfile.
Add that argument into the j_phase_x function.
If our input was correct -> Call j_phase_defused.
Profit….?

Phase 1
Colour coded the different parts. It becomes quite clear that it’s the same functions and registers being used over and over again.

j_printf to print. RCX to hold some string value. j_read_line to take/read input. RAX to take the returned value from a function. j_phase_defused


Stepping into the j_phase_1 function we see that it simply loads a string into rdx and then passes it off to another function named j_strings_not_equal.


In the j_strings_not_equal we see that it first calls to check how long the strings are; which is done by another function that simply loops through the strings and increment a value which is then returned.

It then compares the two strings and does a conditional jz jump to .text:000000014001332A where the args are defined.


It is clear however that one of the strings that are passed are the key to complete the phase 1 challenge.

Key: I am just a renegade hockey mom.


Phase 2
Second one was a little bit trickier compared to the first one. It asks for six numbers to read. The function that asks for it is in turn just calling the c native scanf function that according to docs are asking for six numbers.

Okay, so we need to find six numbers to avoid all the jumps activating the bomb. At .text:00007FF7F2AA2111 it start a for-loop. We can see this by having it increment a value that is moved into EAX with one. Then it compares that value to six, if it isn’t six, it moves on. So we have a loop with a counter to six.

Then it decrease the value of our counter by one. Then it moves that value into RCX. Then it uses RCX to find a value in our buffer and logical shift it once; which tells us its a multiplication by 2. Since if we’re trying to multiply something that is dividable by two then it will rather use the SHL operation. We then compare it to another part of the buffer that uses RAX instead of RCX to locate its value. RAX is the original value of our counter.

So it checks if the previous value is the next value times two.

So if we have a buffer filled with six numbers. [1,2,4,8,16,32]

It will on the first run have the counter 1. Subtract one from that and we have 0, our first element in the list. 1*2 = 2 which is the value of the next element in our buffer; which is located at position 1.


Key: 1 2 4 8 16 32


Phase 3
We can skip first half where it’s just setting things up. What’s interesting here is that we got the same sort of conditional as the previous phase. We have to input two integers otherwise it will activate the bomb.


Before tackling the switch statements its good to see what the phase wants to let us pass. It wants to the value to be greater than five and it needs the second statement to not be equal to 0. So what we need to do is we limit our first input to five and below and the second output needs to become 0.


The only way we will go through this without touching the bomb is by having 5 and -126 as our input to the function. Since that would keep us > 5 and it would make -126 to remain the same number which would make the second case false as well.


Key: 5 -126


Phase 4
Sort of the same scenario here as the one above. We’re calling scanf for two input values. Then checks wether or not we gave exactly two values and if the first value is equal or greater than 15; which we can see by it comparing “Input_one” to 14 with the jle => jump less or equal. By having being a jle instead of jb/ja we might be dealing with a signed value.


Next part is a bit trickier. It has the same logic as the phase 3. We need to have two false values to pass this and not activate the bomb. The program is calling another function, j_func4, that takes our first value as input, 0 (xor edx, edx = 0) and 14. Then it checks if both of our values are not equal to 10.

So what we need are two values where the first one is less or equal to 14 and a second value. Both values needs to be 10 in the end. We see that our second value is not changed in any way. So the second value should be 10.


So this is the second function that takes our first value as well as 0 and 14 as input. Took more time than I'd like to admit to solve this little loop.

By the first go-through it will always be 7, no matter what. So what we need to put in is a value that will help us return 3 so it’s added on top of 7 to be 10. But the value also has to be lower than 10.

So the equation between 7F2AA1F4D — 7F2AA1F6C is => EAX-EDX/2. The two main points to focus on is the CDQ and SAR. SAR EAX, 1 just means that we shift it right with one step; which in turn means a div by two.


It should be fairly easy to brute force and perhaps I did overengineer the solution a bit. It needs to run.

def func4(Input_one, variable_zero, variable_fourteen):

    variable_zero = variable_zero
    variable_seven = int((variable_fourteen - variable_zero) / 2) + variable_zero
    if variable_seven > Input_one:
        return variable_seven + func4(Input_one, variable_zero, variable_seven - 1)
    elif variable_seven >= Input_one:
        return variable_seven
    else:
        return variable_seven + func4(Input_one, variable_seven + 1, variable_fourteen)
    
count = 0
result = func4(count, 0, 14)

while result != 10:
    count+=1
    result = func4(count, 0, 14)

print(count)
Key: 3 10


Phase 5
Decided to add some comments this round to make it easier to read. It follows the same pattern. Input two arguments, these arguments then needs to fit the requirements for the logic gate. Counter should be equal to 15, which means that the loop needs to happen 15 times. arg_sum needs to equal arg_two which means that once it has jumped through the entire buffer it should


Realized that I either need to run this through the debugger several times or map it out by hand on paper to see how it will take all the jumps in the buffer so that the counter equals to 15. So wrote a script and tried some numbers until I got the correct ones.

def phase_5(arg_one, arg_two):

    arg_one = arg_one & 15 
    counter = 0
    arg_sum = 0
    buffer = [10, 2, 14, 7, 8, 12, 15, 11, 0, 4, 1, 13, 3, 9, 6, 5]
    while arg_one != 15:
        counter += 1
        arg_one = buffer[arg_one]
        arg_sum += arg_one

    if counter != 15 or arg_sum != arg_two:
        print(arg_sum, counter)
    else: 
        print(arg_one, arg_two)


phase_5(try_1, try_2)
Key: 5 115


Phase 6
Last phase is a for-loop galore. Contains six for-loops in total with three possible routes to a bomb.


Phase 6 takes in six values just like the phase 2.


It uses a for-loop that counts to six. Then checks every element in the list against two logic gates. It wants our numbers to be between 1–6.


Next one is a for-loop within the loop above. This one checks if the current value in the array that is pointed to by counter exist elsewhere in the array; so no duplicates! If there are….BOMB!


Now to the part is a bit fuzzy for me, still. It starts a new loop. It then moves our variable_node into RAX then moves RAX+8, so the first byte into RAX. Then moves RAX into variable_node again. Looks like it tries to point to a specific offset in variable_node.


It then loads that variable_node value into the position of the counter into our number_array we gave as input.


Between these two some exchange is happening that I couldn’t follow. However, here we see that the last for-loop is based on five. It also loads two nodes into two registers. Where one of them is offset with 8 bits. It then checks if one is greater or equal to the other.

So what it seems to do is that it exchanges our input vales to the values in the node. It then checks if the current node is greater or equal to the next one. It does however seem to skip the first node since the loop starts on one.


So what I did to find all the values was to open up x64dbg set a breakpoint at that cmp operation. Get the value within RAX, transform it into decimal. Sort all of the values and voila!


393 = 4 => 915
1c2 = 2 => 450
212 = 1 => 530
37A = 5 => 890
200 = 6 => 512
215 = 3 => 533

Key: 5 4 3 1 6 2


