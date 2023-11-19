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

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

#define BUFFER_LEN 100

struct sockaddr_in server_addr;

int islogged = 0;

char user_uid[7];
char user_pwd[9];

/* ---- UDP Protocol ---- */

int udp_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        exit(EXIT_FAILURE);
    }

    return fd;
}

void udp_send(int fd, char *msg, size_t n) {
    ssize_t bytes = sendto(fd, msg, n, 0, (struct sockaddr*) &server_addr, sizeof(server_addr));

    if (bytes == -1) {
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP] Sent %ld/%ld bytes: %s", bytes, n, msg);
}

void udp_recv(int fd, char *rsp, size_t n) {
    socklen_t addrlen = sizeof(server_addr);
    ssize_t bytes = recvfrom(fd, rsp, n, 0, (struct sockaddr*) &server_addr, &addrlen);

    if (bytes == -1) {
        exit(EXIT_FAILURE);
    }

    rsp[n-1] = '\0';

    if (DEBUG) printf("[UDP] Got %ld bytes: %s", bytes, rsp);
}

/* ---- Validators ---- */

int validate_user_uid(char *str) {
    if (strlen(str) != 6) return 0;

    char *end = str + 6;

    if (strlen(str) != 6) {
        return 0;
    }

    while (*str != '\0') {
        if ((str == end) || !isdigit(*str++)) {
            return 0;
        }
    }

    return 1;
}

int validate_password(char *str) {
    if (strlen(str) != 8) return 0;

    char *end = str + 8;

    if (strlen(str) != 8) {
        return 0;
    }

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

    if (islogged) {
        printf("You are already logged in.\n");
    }

    if (!validate_user_uid(user_uid)) {
        printf("The UID must be a 6-digit IST student number.\n");
        return;
    }

    if (!validate_password(user_pwd)) {
        printf("The password must be composed of 8 alphanumeric characters.\n");
        return;
    }

    char buffer[50];
    sprintf(buffer, "LIN %s %s\n", user_uid, user_pwd);

    int fd = udp_socket();
    udp_send(fd, buffer, strlen(buffer)+1);
    udp_recv(fd, buffer, sizeof(buffer));
    close(fd);

    if (!strcmp(buffer, "RLI NOK\n")) {
        printf("Incorrect login attempt.\n");
    } else if (!strcmp(buffer, "RLI OK\n")) {
        printf("Successfull login.\n");
        islogged = 1;
    } else if (!strcmp(buffer, "RLI REG\n")) {
        printf("New user registered.\n");
        islogged = 1;
    }
}

void command_logout() {
    char buffer[50];  // message to be send
    sprintf(buffer, "LOU %s %s\n", user_uid, user_pwd);
    
    int fd = udp_socket();
    udp_send(fd, buffer, strlen(buffer)+1);
    udp_recv(fd, buffer, sizeof(buffer));
    close(fd);

    if (!strcmp(buffer, "RLO OK\n")) {
        printf("Successfull logout.\n");
        islogged = 0;
    } else if (!strcmp(buffer, "RLO NOK\n")) {
        printf("Unknown user.\n");
    } else if (!strcmp(buffer, "RLO UNR\n")) {
        printf("User not logged in.\n");
    }
}

void command_unregister() {
    char buffer[50];
    sprintf(buffer, "UNR %s %s\n", user_uid, user_pwd);

    int fd = udp_socket();
    udp_send(fd, buffer, strlen(buffer)+1);
    udp_recv(fd, buffer, sizeof(buffer));
    close(fd);

    if (!strcmp(buffer, "RUR OK")) {
        printf("Successfull unregister.\n");
        islogged = 0;
    } else if (!strcmp(buffer, "RUR NOK")) {
        printf("Unknown user.\n");
    } else if (!strcmp(buffer, "RUR UNR")) {
        printf("Incorrect unregister attempt.\n");
    }
}

void command_exit() {
    if (islogged) {
        printf("Please logout first.\n");
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

        int n;
        char *c = strchr(buffer, ' ');

        if (c) {
            n = c - buffer;
        } else {
            n = strlen(buffer) - 1;
        }
        
        if (!strncmp(buffer, "login", n)) {
            command_login(buffer);
        } else if (!strncmp(buffer, "logout", n)) {
            command_logout();
        } else if (!strncmp(buffer, "unregister", n)) {
            command_unregister();
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