#ifndef _AUX_H_
#define _AUX_H_

#include <sys/types.h>

ssize_t write_all(int fd, char *buffer, ssize_t nbytes);

ssize_t read_all(int fd, char *buffer, ssize_t nbytes);

int startswith(char *prefix, char *str);

#endif