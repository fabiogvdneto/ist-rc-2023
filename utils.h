#ifndef _AUX_H_
#define _AUX_H_

#include <sys/types.h>

void panic(char *str);

int udp_socket();

int tcp_socket();

int startswith(char *prefix, char *str);

#endif