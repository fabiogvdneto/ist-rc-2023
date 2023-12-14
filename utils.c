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