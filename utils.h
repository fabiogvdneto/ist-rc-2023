#ifndef _UTILS_H_
#define _UTILS_H_

#define ERROR_COMMAND_NOT_FOUND \
    "Unknown command. Type 'help' for a list of commands available.\n"
#define ERROR_ALREADY_LOGGED_IN "You are already logged in.\n"
#define ERROR_NOT_LOGGED_IN "You need to login first.\n"
#define ERROR_EXIT_LOGGED_IN "You need to logout first.\n"
#define ERROR_SOCKET "[Error] Could not create socket.\n"
#define ERROR_MMAP "[Error] Failed to map file into memory.\n"
#define ERROR_MUNMAP "[Error] Failed to unmap file from memory.\n"
#define ERROR_SEND_MSG "[Error] Could not send message to server.\n"
#define ERROR_RECV_MSG "[Error] Could not receive message from server.\n"
#define ERROR_CONNECT "[Error] Could not establish connection with server.\n"
#define ERROR_SPRINTF "[Error] sprintf().\n"
#define ERROR_SSCANF "[Error] sscanf().\n"
#define ERROR_OPEN "[Error] Failed to open file.\n"
#define ERROR_MKDIR "[Error] Failed to create directory.\n"
#define ERROR_FSTAT "[Error] Failed to get file attributes.\n"
#define ERROR_FGETS "[Error] Could not read from stdin.\n"
#define ERROR_SIGACTION "[Error] Could not modify signal behaviour.\n"

void panic(char *str);

int udp_socket();

int tcp_socket();

int set_socket_rcvtimeout(int fd, int seconds);

ssize_t read_all_bytes(int fd, char *buffer, ssize_t nbytes);

ssize_t write_all_bytes(int fd, char *buffer, ssize_t nbytes);

int startswith(char *prefix, char *str);

#endif