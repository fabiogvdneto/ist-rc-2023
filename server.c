#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

/* Networking */
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Signals */
#include <signal.h>

/* Files */
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Auction */
#include "auction.h"

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

/* ---- AS File Management ---- */
int create_user_dir(char *uid) {
    char uid_dirname[20];
    char hosted_dirname[30];
    char bidded_dirname[30];

    sprintf(uid_dirname, "USERS/%s", uid);
    if ((mkdir(uid_dirname, 0700)) == -1) {
        return 0;
    }

    sprintf(hosted_dirname, "USERS/%s/HOSTED", uid);
    if ((mkdir(hosted_dirname, 0700)) == -1) {
        rmdir(uid_dirname);
        return 0;
    }

    sprintf(bidded_dirname, "USERS/%s/BIDDED", uid);
    if ((mkdir(bidded_dirname, 0700)) == -1) {
        rmdir(uid_dirname);
        rmdir(hosted_dirname);
        return 0;
    }

    return 1;
}

int erase_user_dir(char *uid) {
    char uid_dirname[20];
    char hosted_dirname[30];
    char bidded_dirname[30];

    sprintf(uid_dirname, "USERS/%s", uid);
    sprintf(hosted_dirname, "USERS/%s/HOSTED", uid);
    sprintf(bidded_dirname, "USERS/%s/BIDDED", uid);

    rmdir(bidded_dirname);
    rmdir(hosted_dirname);
    rmdir(uid_dirname);

    return 1;
}

int create_login(char *uid) {
    char login_name[40];
    FILE *fp;
    
    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    if ((fp = fopen(login_name, "w")) == NULL) {
        return 0;
    }
    fprintf(fp, "Logged in\n");
    fclose(fp);
    return 1;
}

int erase_login(char *uid) {
    char login_name[40];

    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    unlink(login_name);
    return 1;
}

int create_password(char *uid, char *pwd) {
    char pass_name[40];
    FILE *fp;
    
    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(pass_name, "w")) == NULL) {
        return 0;
    }
    fprintf(fp, "%s", pwd);
    fclose(fp);
    return 1;
}

int extract_password(char *uid, char *ext_pwd) {
    char pass_name[40];
    FILE *fp;

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(pass_name, "r")) == NULL) {
        return 0;
    }
    if (fread(ext_pwd, sizeof(char), USER_PWD_LEN, fp) != USER_PWD_LEN) {
        return 0;
    }
    fclose(fp);
    return 1;
}

int erase_password(char *uid) {
    char pass_name[40];

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    unlink(pass_name);
    return 1;
}

// 2 -> não existe diretoria
// 1 -> existe diretoria
// 0 -> erro
int find_user_dir(char *uid) {
    char uid_dirname[20];
    FILE *fp;

    sprintf(uid_dirname, "USERS/%s", uid);
    if ((fp = fopen(uid_dirname, "r")) == NULL) {
        if (errno == ENOENT) {
            return 2;
        } else {
            return 0;
        }
    }
    fclose(fp);
    return 1;
}

/* ---- Responses ---- */

void response_login(int fd, char *uid, char* pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        udp_send(fd, "RLI ERR\n");
    }

    int ret = find_user_dir(uid);
    if (ret == 2) {
        if (!create_user_dir(uid)) {
            printf("ERROR\n");
            return;
            // exit?
        }
        if (!create_login(uid)) {
            erase_user_dir(uid);
            printf("ERROR\n");
            return;
        }
        if (!create_password(uid, pwd)) {
            erase_login(uid);
            erase_password(uid);
            printf("ERROR\n");
            return;
        }
        udp_send(fd, "RLI REG\n");
    } else if (ret == 1) {
        char *ext_pwd = NULL;
        extract_password(uid, ext_pwd);
        if (!strcmp(pwd, ext_pwd)) {
            create_login(uid);
            udp_send(fd, "RLI OK\n");
        } else {
            udp_send(fd, "RLI NOK\n");
        }
    } else if (ret == 0) {
        printf("ERROR\n");
        return;
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
    char buffer[BUFFER_LEN];
    char *label, *delim = " \n";

    int fd = udp_socket();
    udp_bind(fd);
    
    while (1) {
        // TODO: validar formato da mensagem recebida
        // e enviar "ERR" se estiver errado
        udp_recv(fd, buffer);
        if (!(label = strtok(buffer, delim))) continue;
        
        if (!strcmp(label, "LIN")) {
            char *uid = strtok(NULL, delim);
            char *pwd = strtok(NULL, delim);
            response_login(fd, uid, pwd);
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