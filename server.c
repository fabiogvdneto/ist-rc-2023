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

#define BUFFER_LEN 128

struct sockaddr_in server_addr;

int verbose = 0;

/* ---- UDP Protocol ---- */

int udp_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        printf("Error: could not open socket.\n");
        exit(EXIT_FAILURE);
    }

    return fd;
}

void udp_send(int fd, char *msg) {
    size_t n = strlen(msg);
    ssize_t res = sendto(fd, msg, n, 0, (struct sockaddr*) &server_addr, sizeof(server_addr));

    if (res == -1) {
        printf("Error: could not send message to server.\n");
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP] Sent %ld/%ld bytes: %s", res, n, msg);
}

void udp_recv(int fd, char *buffer) {
    socklen_t addrlen = sizeof(server_addr);
    ssize_t res = recvfrom(fd, buffer, BUFFER_LEN, 0, (struct sockaddr*) &server_addr, &addrlen);

    if (res == -1) {
        printf("Error: could not receive message from server.\n");
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP] Received %ld bytes: %s", res, buffer);
}

void udp_bind(int fd) {
    if (bind(fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) {
        exit(EXIT_FAILURE);
    }
}

/* ---- Client Listener ---- */

void extract_label(char *command, char *label, int n) {
    for (int i = 1; (i < n) && (*command != ' ') && (*command != '\n'); i++) {
        *(label++) = *(command++);
    }

    *label = '\0';
}

void client_listener() {
    char buffer[BUFFER_LEN], label[5];

    int fd = udp_socket();
    udp_bind(fd);
    
    while (1) {
        udp_recv(fd, buffer);
        extract_label(buffer, label, sizeof(label));
        
        if (!strcmp(label, "LIN")) {
            udp_send(fd, "RLI OK\n");
        } else if (!strcmp(label, "LOU")) {
            udp_send(fd, "RLO OK\n");
        } else if (!strcmp(label, "UNR")) {
            udp_send(fd, "RUR OK\n");
        } else if (!strcmp(label, "LMA")) {
            udp_send(fd, "RMA OK\n");
        } else if (!strcmp(label, "LMB")) {
            udp_send(fd, "RMB OK\n");
        } else if (!strcmp(label, "LST")) {
            udp_send(fd, "RST OK\n");
        } else if (!strcmp(label, "SRC")) {
            udp_send(fd, "RRC OK\n");
        } else {
            printf("Received unreconizable message: %s\n", buffer);
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