---
layout: post
title: "SLAE Problem 5.3: Msfvenom Analysis of linux/x86/exec"
description: "Analysis of Msfvenom shellcode: linux/x86/exec"
tags: [asm, shellcode, msfvenom]
---


This blog post has been created for completing the requirements for the SecurityTube
Linux Assembly Expert certification:
[<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert)

Student ID: SLAE-824

## Requirements

- Choose at least 3 shellcode samples created using Msfvenom for linux/x86
- Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode
- Present your analysis

### Analysis

For this analysis I have chosen to analyze `linux/x86/exec`. My initial
instinct is that this payload essentially just runs `execve` with
the supplied arguments. Let's see if thats how it plays out!

### The Code

First we need to see what options this payload supports:

{% highlight bash %}
msfvenom --payload linux/x86/exec --list-options

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute
{% endhighlight %}

It looks as though the only basic option is the command we want to run.
Seems logical, lets generate some assembly.

{% highlight bash %}
msfvenom --payload linux/x86/exec CMD="id" -f raw | ndisasm -u -

00000000  6A0B              push byte +0xb
00000002  58                pop eax
00000003  99                cdq
00000004  52                push edx
00000005  66682D63          push word 0x632d
00000009  89E7              mov edi,esp
0000000B  682F736800        push dword 0x68732f
00000010  682F62696E        push dword 0x6e69622f
00000015  89E3              mov ebx,esp
00000017  52                push edx
00000018  E803000000        call dword 0x20
0000001D  696400575389E1CD  imul esp,[eax+eax+0x57],dword 0xcde18953
00000025  80                db 0x80
{% endhighlight %}

Lets break down the code and see what it is doing:

{% highlight bash %}
08048060 <_start>:
 ;; Place 11 in eax
 8048060:	6a 0b                	push   0xb
 8048062:	58                   	pop    eax

{% endhighlight %}

We know from previous exercises that syscall 11 is execve. We
can verify that this code actually calls execve by running
it through libemu:

{% highlight bash %}
msfvenom --payload linux/x86/exec CMD="id" -f raw | /usr/bin/sctest -vvv -S -s 10000 -G exec.dot
{% endhighlight %}

{% highlight bash %}
dot -Tpng exec.dot > exec.png
{% endhighlight %}

<img src="{% asset_path 'exec.png' %}" alt="exec.png" style="width: 500px;"/>

Sure enough we can see that it does in fact call execve as hypothesized. Let's
keep going:

{% highlight bash %}
 ;; Clear out edx by sign extending eax
 8048063:	99                   	cdq

 ;; Push 0x00000000, which is now the value of edx
 ;; onto the stack to null terminate string
 8048064:	52                   	push   edx

 ;; Push -c argument on the stack
 8048065:	66 68 2d 63          	pushw  0x632d <--- c-


 ;; Save a pointer to the argument in edi
 8048069:	89 e7                	mov    edi,esp

 ;; Push the string /bin/sh onto the stack
 804806b:	68 2f 73 68 00       	push   0x68732f <--- hs/
 8048070:	68 2f 62 69 6e       	push   0x6e69622f <--- nib/

 ;; Put a pointer to /bin/sh into ebx
 8048075:	89 e3                	mov    ebx,esp

 ;; Push 0x00000000 again onto the stack...
 8048077:	52                   	push   edx

 ;; call 0x20 is executing byte 32
 ;; from the beginning of the shellcode
 ;; byte 32 starts with 57
 8048078:	e8 a3 7f fb f7       	call   20 <_start-0x8048040>
 804807d:	69 64 00 57 53 89 e1 	imul   esp,DWORD PTR [eax+eax*1+0x57],0xcde18953
 8048084:	cd
 8048085:	80                   	.byte 0x80
{% endhighlight %}

Since the call instruction is executing code at an offset in the
shellcode our disassembler has failed us making the instructions
after the call seem random and non-sensical. libemu seems to
have gotten them right but we can also drop the bytes
`57 53 89 e1 cd 80` into our favorite online disassembler
[here](https://defuse.ca/online-x86-assembler.htm#disassembly2).
Another trick is to use a bit of perl like so:

{% highlight bash %}
perl -e 'print "\x57\x53\x89\xe1\xcd\x80"' > shellcode

ndisasm -b 32 shellcode
{% endhighlight %}

Looking at the results we get:

{% highlight bash %}
0:  57                      push   edi
1:  53                      push   ebx
2:  89 e1                   mov    ecx,esp
4:  cd 80                   int    0x80
{% endhighlight %}

These look a little more logical. Before we talk about
these instructions though, what about the bytes `69 64 00`
that lie between the call instruction and these bytes
that we just disassembled and that the call instruction
is invoking?

We know `00` is often used to null terminate
a string. We also know that `69 64` falls within the range
of ascii values. Consulting the ascii table we determine that
69 is lowercase `i` and 64 is lowercase `d`. Right! this is the
command that we configured to run on the machine... `id`.
We also know that a call instruction places the next instruction
onto the stack. This means that `69 64 00 57` would be placed
on the stack. The 57 will never be reached because the null
terminator will terminate the string.

Next, the values of edi (the pointer to the -c argument) and ebx (the
pointer to /bin/sh) are pushed onto the stack. Since a pointer to
the string `id` was already pushed onto the stack via the invocation
of the `call` instruction, the stack will contain `/bin/sh -c id`.
A pointer to those arguments are placed into ecx.

We can confirm this by loading our code in the usual sample program
and using GDB to step through the program and look at the state
of the stack.

{% highlight bash %}
(gdb) x/20xw $esp
0xbfffeb9e:	0xbfffebae	0xbfffebb6	0x0804a05d	0x00000000
0xbfffebae:	0x6e69622f	0x0068732f	0x0000632d	0x84040000
0xbfffebbe:	0xc3c40804	0xf000b7fb	0x841bb7ff	0xa0400804
0xbfffebce:	0x84100804	0x00000804	0x00000000	0xaaf30000
0xbfffebde:	0x0001b7e2	0xec740000	0xec7cbfff	0xcccabfff
(gdb) x/s 0xbfffebae
0xbfffebae:	"/bin/sh"
(gdb) x/s 0xbfffebb6
0xbfffebb6:	"-c"
(gdb) x/s 0x0804a05d
0x804a05d <buf+29>:	"id"
(gdb)
(gdb) i r
eax            0xb	11
ecx            0xbfffeb9e <--- pointing to top of the stack
{% endhighlight %}

Reminding ourselves of the signature of `execve` we see:

{% highlight c %}
int execve(const char *path, char *const argv[], char *const envp[]);
{% endhighlight %}

{% highlight bash %}
We have eax as 0xb or sys call 11 (execve)
We have ebx as the string /bin/sh
We have ecx as a pointer to the function arguments,
the first being the name of the program /bin/sh
the second being -c
the third being the command id.
We have edx as 0x00000000 which is NULL

{% endhighlight %}

We then call our `int 0x80` interupt and execute our command.

