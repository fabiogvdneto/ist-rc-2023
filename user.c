#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define DEBUG 1

#define PORT_FLAG "-p"
#define IP_FLAG "-n"

#define DEFAULT_PORT 58069
#define DEFAULT_IP "127.0.0.1"

struct sockaddr_in server_addr;

int islogged = 0;

char user_uid[7];
char user_pwd[9];

/* ---- UDP Protocol ---- */

void udp_send_message(char *msg) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        exit(EXIT_FAILURE);
    }

    ssize_t bytes = sendto(fd, msg, sizeof(msg), 0, (struct sockaddr*) &server_addr, sizeof(server_addr));
    if (bytes == -1) {
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP SENT] %s (%ld bytes)\n", msg, bytes);
    
    close(fd);
}

/* ---- Validators ---- */

int validate_user_uid(char *str) {
    char *end = str + 6;

    while (*str != '\0') {
        if ((str == end) || !isdigit(*str++)) {
            return 0;
        }
    }

    return 1;
}

int validate_password(char *str) {
    char *end = str + 8;

    while (*str != '\0') {
        if ((str == end) || !isalnum(*str++)) {
            return 0;
        }
    }

    return 1;
}

/* ---- Commands ---- */

void command_login(char *command) {
    sscanf(command, "login %s %s\n", user_uid, user_pwd);

    if (!validate_user_uid(user_uid)) {
        printf("The UID must be a 6-digit IST student number.\n");
        return;
    }

    if (!validate_password(user_pwd)) {
        printf("The password must be composed of 8 alphanumeric characters.\n");
        return;
    }

    char msg[20];
    sprintf(msg, "LIN %s %s", user_uid, user_pwd);
    udp_send_message(msg);

    // missing: response from AS

    islogged = 1;
}

void command_logout() {
    char msg[20];
    sprintf(msg, "LOU %s %s", user_uid, user_pwd);
    udp_send_message(msg);

    // missing: response from AS

    islogged = 0;
}

void command_exit() {
    if (islogged) {
        printf("Please execute logout from the Auction Server first.\n");
        return;
    }

    exit(EXIT_SUCCESS);
}

/* ---- Command Listener ---- */

void parse_command() {
    char buffer[100];

    while (1) {
        printf("> ");
        
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            exit(1);
        }

        char *space = strchr(buffer, ' ');
        int n;

        if (space) {
            n = strchr(buffer, ' ') - buffer;
        } else {
            n = strlen(buffer) - 1;
        }
        
        if (!strncmp(buffer, "login", n)) {
            command_login(buffer);
        } else if (!strncmp(buffer, "logout", n)) {
            command_logout();
        } else if (!strncmp(buffer, "unregister", n)) {
            
        } else if (!strncmp(buffer, "exit", n)) {
            command_exit();
        } else if (!strncmp(buffer, "open", n)) {
            
        } else if (!strncmp(buffer, "close", n)) {
            
        } else if (!strncmp(buffer, "myactions", n) || !strncmp(buffer, "ma", n)) {
            
        } else if (!strncmp(buffer, "mybids", n) || !strncmp(buffer, "mb", n)) {
            
        } else if (!strncmp(buffer, "list", n) || !strncmp(buffer, "l", n)) {
            
        } else if (!strncmp(buffer, "show_asset", n) || !strncmp(buffer, "sa", n)) {
            
        } else if (!strncmp(buffer, "bid", n)) {
            
        } else if (!strncmp(buffer, "show_record", n)) {
            
        } else {
            printf("Command not found.\n");
        }
    }
}

/* ---- Initialization ---- */

int main(int argc, char **argv) {
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(DEFAULT_IP);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], IP_FLAG)) {
            server_addr.sin_addr.s_addr = inet_addr(argv[++i]);
        } else if (!strcmp(argv[i], PORT_FLAG)) {
            server_addr.sin_port = htons(atoi(argv[++i]));
        } else {
            printf("tu es estupido vai po crl");
            exit(EXIT_FAILURE);
        }
    }

    parse_command();
    return 1;
}