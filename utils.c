#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/socket.h>
#include <sys/time.h>
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

int set_socket_rcvtimeout(int fd, int seconds) {
    struct timeval timeout = { .tv_sec = seconds, .tv_usec = seconds*1000 };
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

/* ---- Read & Write ---- */

ssize_t read_all_bytes(int fd, char *buffer, ssize_t nbytes) {
    ssize_t res, readd = 0;
    while ((res = read(fd, buffer+readd, nbytes-readd)) > 0) {
        readd += res;
    }

    if ((res == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
        perror("read");
        return res;
    }

    return readd;
}

ssize_t write_all_bytes(int fd, char *buffer, ssize_t nbytes) {
    ssize_t res, written = 0;
    while (written < nbytes) {
        res = write(fd, buffer+written, nbytes-written);
        if (res == -1) return res;
        written += res;
    }

    return written;
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