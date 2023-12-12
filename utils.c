#ifndef _UTILS_H_
#define _UTILS_H_

#include <unistd.h>
#include "utils.h"

/* ---- Read & Write ---- */

ssize_t write_all(int fd, char *buffer, ssize_t nbytes) {
    ssize_t res, written = 0;
    while ((res = write(fd, buffer+written, nbytes-written)) > 0) {
        written += res;
    }
    return (res == -1) ? res : written;
}

ssize_t read_all(int fd, char *buffer, ssize_t nbytes) {
    ssize_t res, readd = 0;
    while (nbytes && ((res = read(fd, buffer+readd, nbytes)) > 0)) {
        readd += res;
        nbytes -= res;
        if (*(buffer+readd-1) == '\n') {
            break;
        }

    }
    return (res == -1) ? res : readd;
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