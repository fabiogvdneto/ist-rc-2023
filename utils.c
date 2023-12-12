#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"

void panic(char *str) {
    fprintf(stderr, "%s", str);
    exit(EXIT_FAILURE);
}

/* ---- Sockets ---- */

int udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

int tcp_socket() {
    return socket(AF_INET, SOCK_STREAM, 0);
}

/* ---- Validators ---- */

/**
 * This fucntion is similar to strspn() builtin function, but the initial segment can only be 
 * located at the start of the string.
 * Returns the number of bytes from prefix that matches the given string.
*/
int startswith(char *prefix, char *str) {
    char *start = str;
    while (*prefix && (*prefix++ == *str++));
    return (str - start);
}

#endif