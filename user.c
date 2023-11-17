#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define DEFAULT_PORT "58069"

#define PORT_FLAG "-p"
#define IP_FLAG "-n"

char hostname[128];
char ip[INET_ADDRSTRLEN];
char port[6];

void set_default_ip() {
    if (gethostname(hostname, sizeof(hostname)) == -1) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(-1);
    }

    struct addrinfo hints, *res;
    struct in_addr *addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int errcode = getaddrinfo(hostname, NULL, &hints, &res);

    if (errcode) {
        fprintf(stderr, "error: getaddrinfo: %s\n", gai_strerror(errcode));
        exit(-1);
    }

    while (res) {
        addr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
        inet_ntop(res->ai_family, addr, ip, sizeof(ip));
        res = res->ai_next;
    }
}

int main(int argc, char **argv) {
    set_default_ip();
    strcpy(port, DEFAULT_PORT);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], IP_FLAG)) {
            strcpy(ip, argv[++i]);
        } else if (strcmp(argv[i], PORT_FLAG)) {
            strcpy(port, argv[++i]);
        } else {
            printf("tu es estupido vai po crl");
            exit(0);
        }
    }

    printf("%s %s\n", ip, port);
    return 1;
}