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
  printf("The size of a sockaddr_in is: %x\n",sizeof(config));
  printf("The size of a sockaddr * is: %x\n", sizeof((struct sockaddr *)&config));
  
};
