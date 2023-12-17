#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"

void debug(char *str, ...) {
    if (DEBUG) {
        va_list ap;
        va_start(ap, str);
        vprintf(str, ap);
        va_end(ap);
    }
}

/* ---- Read & Write ---- */

ssize_t read_all_bytes(int fd, char *buffer, ssize_t nbytes) {
    ssize_t res, readd = 0;
    while ((res = read(fd, buffer+readd, nbytes-readd)) > 0) {
        readd += res;
    }

    if ((res == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
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

ssize_t read_file_data(int sockfd, FILE *file, off_t nbytes) {
    ssize_t ret;
    size_t to_read;
    char buffer[BUFSIZ_L];
    while (nbytes > 0) {
        to_read = (nbytes > BUFSIZ_L) ? BUFSIZ_L : nbytes;

        ret = read_all_bytes(sockfd, buffer, to_read);
        if (ret == -1) {
            perror("read");
            return ret;
        }

        if (ret == 0) return nbytes; // Timeout

        if (fwrite(buffer, sizeof(char), to_read, file) < to_read) {
            perror("fwrite");
            return ret;
        }

        nbytes -= to_read;
    }

    return nbytes;
}

ssize_t write_file_data(int sockfd, FILE *file, off_t nbytes) {
    size_t to_write;
    char buffer[BUFSIZ_L];
    while (nbytes > 0) {
        to_write = (nbytes > BUFSIZ_L) ? BUFSIZ_L : nbytes;

        if (fread(buffer, sizeof(char), to_write, file) < to_write) {
            perror("fread");
            return nbytes;
        }

        if (write_all_bytes(sockfd, buffer, to_write) == -1) {
            perror("write");
            return nbytes;
        }

        nbytes -= to_write;
    }

    return nbytes;
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

int substring(char *str, char stop, int len) {
    for (int i = 0; (i < len) && (str[i] != '\0'); i++) {
        if (str[i] == stop) {
            str[i] = '\0';
            return i+1;
        }
    }

    return -1;
}
