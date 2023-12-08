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
#include <dirent.h>

/* Auction */
#include "auction.h"

/* Roadmap (server.c) 
- fazer resposta ao open
*/

#define DEBUG 1

#define PORT_FLAG "-p"
#define VERB_FLAG "-v"

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

#define BUFFER_LEN 128
#define BIG_BUFFER_LEN 6144

#define NON_EXIST 2
#define SUCCESS 1
#define ERROR 0

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
    ssize_t res = recvfrom(fd, buffer, BUFSIZ_S, 0, (struct sockaddr*) &server_addr, &addrlen);

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
        return ERROR;
    }

    sprintf(hosted_dirname, "USERS/%s/HOSTED", uid);
    if ((mkdir(hosted_dirname, 0700)) == -1) {
        rmdir(uid_dirname);
        return ERROR;
    }

    sprintf(bidded_dirname, "USERS/%s/BIDDED", uid);
    if ((mkdir(bidded_dirname, 0700)) == -1) {
        rmdir(uid_dirname);
        rmdir(hosted_dirname);
        return ERROR;
    }

    return SUCCESS;
}

int erase_dir(char *dirname) {
    DIR *d = opendir(dirname);
    int r = -1;

    if (d) {
        struct dirent *p;

        r = 0;
        while (!r && (p = readdir(d))) {
            int r2 = -1;
            char buffer[BUFSIZ_L];

            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
                continue;
            }

            struct stat statbuf;

            sprintf(buffer, "%s/%s", dirname, p->d_name);
            if (!stat(buffer, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode)) {
                    r2 = erase_dir(buffer);
                } else {
                    r2 = unlink(buffer);
                }
            }
            r = r2;
        }
        closedir(d);
    }

    if (!r) {
        r = rmdir(dirname);
    }

    return r;
}

int erase_user_dir(char *uid) {
    char uid_dirname[20];

    sprintf(uid_dirname, "USERS/%s", uid);
    erase_dir(uid_dirname);

    return SUCCESS;
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
            return NON_EXIST;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int create_login(char *uid) {
    char login_name[40];
    FILE *fp;
    
    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    if ((fp = fopen(login_name, "w")) == NULL) {
        return ERROR;
    }
    fprintf(fp, "Logged in\n");
    fclose(fp);
    return SUCCESS;
}

int erase_login(char *uid) {
    char login_name[40];

    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    unlink(login_name);
    return SUCCESS;
}

// 2 -> não existe ficheiro de login
// 1 -> existe ficheiro de login
// 0 -> erro
int find_login(char *uid) {
    char login_name[40];
    FILE *fp;

    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    if ((fp = fopen(login_name, "r")) == NULL) {
        if (errno == ENOENT) {
            return NON_EXIST;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int create_password(char *uid, char *pwd) {
    char pass_name[40];
    FILE *fp;
    
    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(pass_name, "w")) == NULL) {
        return ERROR;
    }
    fprintf(fp, "%s", pwd);
    fclose(fp);
    return SUCCESS;
}

int extract_password(char *uid, char *ext_pwd) {
    char pass_name[40];
    FILE *fp;

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(pass_name, "r")) == NULL) {
        return ERROR;
    }

    if (fread(ext_pwd, sizeof(char), USER_PWD_LEN, fp) != USER_PWD_LEN) {
        return ERROR;
    }

    fclose(fp);
    return SUCCESS;
}

int erase_password(char *uid) {
    char pass_name[40];

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    unlink(pass_name);
    return SUCCESS;
}

/* ---- Responses ---- */

void response_login(int fd, char *uid, char* pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        udp_send(fd, "RLI ERR\n");
        return;
    }

    int ret = find_user_dir(uid);
    if (ret == NON_EXIST) {
        if (create_user_dir(uid) == ERROR) {
            printf("ERROR\n");
            return;
            // exit?
        }
        if (create_login(uid) == ERROR) {
            erase_user_dir(uid);
            printf("ERROR\n");
            return;
        }
        if (create_password(uid, pwd) == ERROR) {
            erase_login(uid);
            erase_password(uid);
            printf("ERROR\n");
            return;
        }
        udp_send(fd, "RLI REG\n");
    } else if (ret == SUCCESS) {
        // TODO: check if user is already logged in
        char ext_pwd[USER_PWD_LEN];
        extract_password(uid, ext_pwd);
        if (!strcmp(pwd, ext_pwd)) {
            create_login(uid);
            udp_send(fd, "RLI OK\n");
        } else {
            udp_send(fd, "RLI NOK\n");
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    }
}

void response_logout(int fd, char *uid, char *pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        udp_send(fd, "RLO ERR\n");
    }

    int ret = find_user_dir(uid);
    if (ret == NON_EXIST) {
        udp_send(fd, "RLO UNR\n");
    } else if (ret == SUCCESS) {
        // é necessário verificar se as passwords são iguais?
        char ext_pwd[USER_PWD_LEN];
        extract_password(uid, ext_pwd);
        if (!strcmp(pwd, ext_pwd)) {
            int ret2 = find_login(uid);
            if (ret2 == SUCCESS) {
                erase_login(uid);
                udp_send(fd, "RLO OK\n");
            } else if (ret2 == NON_EXIST) {
                udp_send(fd, "RLO NOK\n");
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
            }
        } else {
            udp_send(fd, "RLO ERR\n");
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    }
}

void response_unregister(int fd, char *uid, char *pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        udp_send(fd, "RUR ERR\n");
    }

    int ret = find_user_dir(uid);
    if (ret == NON_EXIST) {
        udp_send(fd, "RUR UNR\n");
    } else if (ret == SUCCESS) {
        // é necessário verificar se as passwords são iguais?
        char ext_pwd[USER_PWD_LEN];
        extract_password(uid, ext_pwd);
        if (!strcmp(pwd, ext_pwd)) {
            int ret2 = find_login(uid);
            if (ret2 == SUCCESS) {
                erase_user_dir(uid);
                udp_send(fd, "RUR OK\n");
            } else if (ret2 == NON_EXIST) {
                udp_send(fd, "RUR NOK\n");
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
            }
        } else {
            udp_send(fd, "RUR ERR\n");
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
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
    char buffer[BUFSIZ_S];
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
            char *uid = strtok(NULL, delim);
            char *pwd = strtok(NULL, delim);
            response_logout(fd, uid, pwd);
            udp_send(fd, "RLO OK\n");
        } else if (!strcmp(label, "UNR")) {
            char *uid = strtok(NULL, delim);
            char *pwd = strtok(NULL, delim);
            response_unregister(fd, uid, pwd);
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