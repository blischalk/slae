---
layout: post
title: "SLAE Problem 4: Custom Encoding Scheme"
description: "A demonstration of a custom encoding scheme"
tags: [asm, shellcode, c, encoding]
---

# Assignment 4

This blog post has been created for completing the requirements for the SecurityTube
Linux Assembly Expert certification:
[<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert)

Student ID: SLAE-824

## Requirements

- Create a custom encoding scheme like the “Insertionon Encoder” we showed you
- PoC with using execve-stack as the shellcode to encode with your schema and execute

## Source Code

The source code for this article can be found [here](https://github.com/blischalk/slae/tree/master/exercise4)

## Strategy

My strategy for fulfulling this assignment will be the following:

- Think about what sort of encoding algorithm I want to used
- Write a python program that will take the execve-stack shellcode and encode it using the algorithm I decide on
- Write an assembly program that contains the encoded shellcode, decodes, and then executes it

## Encoding Algorithm

So what sort of algorithm shall I write? Off the top of my head I'm thinking
of an cycling encoder. Something like the following:

- Jump, Call, Pop our shellcde location into esi
- Think of a dword such as `0xdeadbeef`.
- Initialize eax and ebx with the dword
- Initialize edx to zero. This will be our offset.
- Place the length of the shellcode in ecx
- Loop based on ecx executing the following
  - if ebx is 0x00000000, re-initialize it with eax
  - Xor the offset of shellcode with the lowest significant byte of ebx (bl)
  - Increment our offset
  - Shift right ebx making the second least significant byte the least significant byte
- Jump to our decoded shellcode after looping has been exhausted


The algorithm sounds like it should work... Let's give it a shot

## The Assembly

{% highlight nasm %}

global _start
section .text
  _start:
    jmp short call_decoder

  decoder:
    pop esi
    mov eax, decoderring
    xor edx, edx
    mov ecx, 0xxx

  reset:
    mov ebx, decoderring

  decode:
    cmp ebx, 0x00000000
    jz reset
    xor [esi+edx], bl
    inc edx
    shr ebx, 0x8
    loop decode
    jmp esi

  call_decoder:
    call decoder
    encoded: dd "xxxxxxxxxxxxxxxxxxxxx"
    decoderring: dword 0xdeadbeef

{% endhighlight %}

## The Python

{% highlight python %}

#!/usr/bin/python
'''
Author: Brett Lischalk
Title: Cycling Encoder
Description:
Cycles through a dword using the
lowest significant byte as the value to xor
a byte of shellcode with.
'''

# Set the dword you want to be your
# value to cycle through in encoder
encoder=0xdeadbeef
encoder_dirty=encoder
shellcode="shellcode goes here................"
encoded=bytearray()
shellcode_bytes=bytearray(shellcode)

while len(shellcode_bytes) != 0:
  # when we have shifted our decoder to zero
  # we want to reset it to begin the cycle again
  if encoder_dirty == 0x00000000:
    encoder_dirty = encoder

  # get the first and rest of our shellcode
  f, r            = shellcode_bytes[0], shellcode_bytes[1:]
  # get the lowest significant byte of our decoder
  # xor the current shellcode byte
  # append it to our encoded shellcode
  encoded.append(f ^ (encoder_dirty & 0xff))

  # update our shellcode to be the shellcode
  # minus the first byte
  shellcode_bytes = r

  # shift off the lowest significant byte
  encoder_dirty   = encoder_dirty >> 8

# Format our bytes as hex for output
formatted = [hex(b) for b in encoded]

print "Shellcode Length: %s" % len(formatted)
print(",".join(formatted))

{% endhighlight %}

Let's try encoding the execve-stack shellcode, placing it
in our decoder assembly program, extracting the bytes and
placing those in our shellcode.c stub and see if we get a
bind shell as we would hope.

Grab the bytes of execve-stack shellcode:

{% highlight bash %}
objdump -d ./execve-stack|grep '[0-9a-f]:'\
| grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '\
|tr -s ' '|tr '\t' ' ' |sed 's/ $//g'|\
sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

{% endhighlight %}

Throw the bytes in our python decoder program:

{% highlight python %}

# Set the dword you want to be your
# value to cycle through in encoder
encoder=0xdeadbeef
encoder_dirty=encoder
shellcode="\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

encoded=bytearray()
shellcode_bytes=bytearray(shellcode)

while len(shellcode_bytes) != 0:
  # when we have shifted our decoder to zero
  # we want to reset it to begin the cycle again
  if encoder_dirty == 0x00000000:
    encoder_dirty = encoder

  # get the first and rest of our shellcode
  f, r            = shellcode_bytes[0], shellcode_bytes[1:]
  # get the lowest significant byte of our decoder
  # xor the current shellcode byte
  # append it to our encoded shellcode
  encoded.append(f ^ (encoder_dirty & 0xff))

  # update our shellcode to be the shellcode
  # minus the first byte
  shellcode_bytes = r

  # shift off the lowest significant byte
  encoder_dirty   = encoder_dirty >> 8

# Format our bytes as hex for output
formatted = [hex(b) for b in encoded]

print "Shellcode Length: %s" % len(formatted)
print(",".join(formatted))


{% endhighlight %}

Throw the bytes and shellcode length in our `decoder.nasm`

{% highlight nasm %}

global _start
section .text
  _start:
    jmp short call_decoder

  decoder:
    pop esi
    mov eax, [decoderring]
    xor edx, edx
    xor edi, edi
    mov ecx, 25 ; encoded shellcode length

  reset:
    mov ebx, [decoderring]

  decode:
    cmp ebx, edi
    jz reset
    xor [esi+edx], bl
    inc edx
    shr ebx, 0x8
    loop decode
    jmp esi

  call_decoder:
    call decoder
    encoded: db 0xde,0x7e,0xfd,0xb6,0xc0,0x91,0xc1,0xad,0x87,0x91,0xcf,0xb7,0x81,0x37,0x4e,0x8e,0x66,0x5c,0xfe,0x57,0xe,0xe,0xa6,0x13,0x6f
    decoderring: dd 0xdeadbeef

{% endhighlight %}

Compile, get the bytes, and load into shellcode.c stub:

{% highlight c %}

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\xeb\x23\x5e\xa1\xa3\x80\x04\x08\x31\xd2\xb9\x19\x00\x00\x00\x8b\x1d\xa3\x80\x04\x08\x83\xfb\x00\x74\xf5\x30\x1c\x16\x42\xc1\xeb\x08\xe2\xf2\xff\xe6\xe8\xd8\xff\xff\xff\xde\x7e\xfd\xb6\xc0\x91\xc1\xad\x87\x91\xcf\xb7\x37\x4e\x8e\x66\x5c\xfe\x57\x0e\x0e\xa6\x13\x6f\xef\xef\xbe\xad\xde";


main()
{

	printf("Shellcode Length:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();

}

{% endhighlight %}


