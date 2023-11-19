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
#define VERB_FLAG "-v"

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

struct sockaddr_in server_addr;

int verbose = 0;
int islogged = 0;

char user_uid[7];
char user_pwd[9];

/* ---- UDP Protocol ---- */

int udp_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        printf("Error: could not open socket.\n");
        exit(EXIT_FAILURE);
    }

    return fd;
}

void udp_send(int fd, char *msg, size_t n) {
    ssize_t bytes = sendto(fd, msg, n, 0, (struct sockaddr*) &server_addr, sizeof(server_addr));

    if (bytes == -1) {
        printf("Error: could not send message to client.\n");
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP] Sent %ld/%ld bytes: %s", bytes, n, msg);
}

void udp_recv(int fd, char *rsp, size_t n) {
    socklen_t addrlen = sizeof(server_addr);
    ssize_t bytes = recvfrom(fd, rsp, n, 0, (struct sockaddr*) &server_addr, &addrlen);

    if (bytes == -1) {
        printf("Error: could not receive message from client.\n");
        exit(EXIT_FAILURE);
    }

    rsp[n-1] = '\0';

    if (DEBUG) printf("[UDP] Received %ld bytes: %s", bytes, rsp);
}

void udp_bind(int fd) {
    if (bind(fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) {
        exit(EXIT_FAILURE);
    }
}

/* ---- Client Listener ---- */

void client_listener() {
    char msg[50];

    int fd = udp_socket();
    udp_bind(fd);
    
    while (1) {
        udp_recv(fd, msg, sizeof(msg));

        char *c = strchr(msg, ' ');
        int n;

        if (c) {
            n = c - msg;
        } else {
            n = strlen(msg) - 1;
        }
        
        if (!strncmp(msg, "LIN", n)) {
            udp_send(fd, "RLI OK\n", 8);
        } else if (!strncmp(msg, "LOU", n)) {
            udp_send(fd, "RLO OK\n", 8);
        } else if (!strncmp(msg, "UNR", n)) {
            udp_send(fd, "RUR OK\n", 8);
        } else if (!strncmp(msg, "LMA", n)) {
            udp_send(fd, "RMA OK\n", 8);
        } else if (!strncmp(msg, "LMB", n)) {
            udp_send(fd, "RMB OK\n", 8);
        } else if (!strncmp(msg, "LST", n)) {
            udp_send(fd, "RST OK\n", 8);
        } else if (!strncmp(msg, "SRC", n)) {
            udp_send(fd, "RRC OK\n", 8);
        } else {
            printf("Received unreconizable message: %s\n", msg);
        }
    }

    close(fd);
}

/* ---- Initialization ---- */

int main(int argc, char **argv) {
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(DEFAULT_IP);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], VERB_FLAG)) {
            verbose = 1;
        } else if (!strcmp(argv[i], PORT_FLAG)) {
            server_addr.sin_port = htons(atoi(argv[++i]));
        } else {
            printf("tu es estupido vai po crl");
            exit(EXIT_FAILURE);
        }
    }

    client_listener();
}