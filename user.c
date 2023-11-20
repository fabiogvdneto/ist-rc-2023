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

/* TODOs

- select()
- Timers (setsockopt()).
- Signals (SIGSEGV, SIGINT ctrl-c, SIGCHLD server-side, SIGPIPE).
- Um processo para cada cliente.

*/

#define DEBUG 1

#define PORT_FLAG "-p"
#define IP_FLAG "-n"

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

#define BUFFER_LEN 128

struct sockaddr_in server_addr;

int islogged = 0;

char user_uid[7];
char user_pwd[9];

/* ---- UDP Protocol ---- */

int udp_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        printf("Error: could not open UDP socket.\n");
        exit(EXIT_FAILURE);
    }

    return fd;
}

void udp_send(int fd, char *msg) {
    size_t n = strlen(msg);
    ssize_t bytes = sendto(fd, msg, n, 0, (struct sockaddr*) &server_addr, sizeof(server_addr));

    if (bytes == -1) {
        printf("Error: could not send message to server.\n");
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP] Sent %ld/%ld bytes: %s", bytes, n, msg);
}

void udp_recv(int fd, char *buffer) {
    socklen_t addrlen = sizeof(server_addr);
    ssize_t bytes = recvfrom(fd, buffer, (BUFFER_LEN-1), 0, (struct sockaddr*) &server_addr, &addrlen);

    if (bytes == -1) {
        printf("Error: could not receive message from server.\n");
        exit(EXIT_FAILURE);
    }

    buffer[bytes] = '\0';

    if (DEBUG) printf("[UDP] Received %ld bytes: %s", bytes, buffer);
}

/* ---- TCP Protocol ---- */

int tcp_socket() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1) {
        printf("Error: could not open TCP socket.\n");
        exit(EXIT_FAILURE);
    }

    return fd;
}

void tcp_conn(int fd) {
    if (connect(fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) {
        printf("Error: could not connect to server socket.");
        exit(EXIT_FAILURE);
    }
}

void tcp_write(int fd, char *msg) {
    size_t n = strlen(msg);
    ssize_t bytes = write(fd, msg, n);

    // Missing: while (1) { write... }

    if (bytes == -1) {
        printf("Error: could not write message to server.\n");
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[TCP] Sent %ld/%ld bytes: %s", bytes, n, msg);
}

void tcp_read(int fd, char *buffer) {
    ssize_t bytes = read(fd, buffer, BUFFER_LEN);

    // Missing: while (1) { read... }

    if (bytes == -1) {
        printf("Error: could not write message to server.\n");
        exit(EXIT_FAILURE);
    }

    buffer[bytes] = '\0';

    if (DEBUG) printf("[TCP] Received %ld bytes: %s", bytes, buffer);
}

/* ---- Validators ---- */

int validate_user_uid(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i == 6);
}

int validate_password(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }

    return (i == 8);
}

/* ---- Commands ---- */

void command_login(char *command) {
    char temp_uid[BUFFER_LEN];
    char temp_pwd[BUFFER_LEN];
    sscanf(command, "login %s %s\n", temp_uid, temp_pwd);
    
    if (islogged) {
        printf("You are already logged in.\n");
        return;
    }

    if (!validate_user_uid(temp_uid)) {
        printf("The UID must be a 6-digit IST student number.\n");
        return;
    }

    if (!validate_password(temp_pwd)) {
        printf("The password must be composed of 8 alphanumeric characters.\n");
        return;
    }

    strcpy(user_uid, temp_uid);
    strcpy(user_pwd, temp_pwd);

    char buffer[BUFFER_LEN];
    sprintf(buffer, "LIN %s %s\n", user_uid, user_pwd);

    int fd = udp_socket();
    udp_send(fd, buffer);
    udp_recv(fd, buffer);
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
    if (!islogged) {
        printf("User not logged in.");
        return;
    }

    char buffer[BUFFER_LEN];  // message to be send
    sprintf(buffer, "LOU %s %s\n", user_uid, user_pwd);
    
    int fd = udp_socket();
    udp_send(fd, buffer);
    udp_recv(fd, buffer);
    close(fd);

    if (!strcmp(buffer, "RLO OK\n")) {
        printf("Successfull logout.\n");
        islogged = 0;
    } else if (!strcmp(buffer, "RLO NOK\n")) {
        printf("User not logged in.\n");
    } else if (!strcmp(buffer, "RLO UNR\n")) {
        printf("Unknown user.\n");
    }
}

void command_unregister() {
    if (!islogged) {
        printf("User not logged in.");
        return;
    }
    
    char buffer[BUFFER_LEN];
    sprintf(buffer, "UNR %s %s\n", user_uid, user_pwd);

    int fd = udp_socket();
    udp_send(fd, buffer);
    udp_recv(fd, buffer);
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
        printf("You need to logout first.\n");
        return;
    }

    exit(EXIT_SUCCESS);
}

void command_open(char *command) {
    char name[BUFFER_LEN];
    char asset_fname[BUFFER_LEN];
    char start_value[BUFFER_LEN];
    char timeactive[BUFFER_LEN];

    sscanf(command, "open %s %s %s %s\n", name, asset_fname, start_value, timeactive);

    char buffer[BUFFER_LEN];
    sprintf(buffer, "OPA %s %s %s %s %s %s %s %s\n", user_uid, user_pwd,
                    name, start_value, timeactive, asset_fname);
}

/* ---- Command Listener ---- */

void extract_label(char *command, char *label, int n) {
    for (int i = 1; (i < n) && (*command != ' ') && (*command != '\n'); i++) {
        *(label++) = *(command++);
    }

    *label = '\0';
}

void command_listener() {
    char buffer[BUFFER_LEN], label[20];

    while (1) {
        printf("> ");
        
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            printf("Error: could not read from stdin.\n");
            exit(EXIT_FAILURE);
        }

        extract_label(buffer, label, sizeof(label));
        
        if (!strcmp(label, "login")) {
            command_login(buffer);
        } else if (!strcmp(label, "logout")) {
            command_logout();
        } else if (!strcmp(label, "unregister")) {
            command_unregister();
        } else if (!strcmp(label, "exit")) {
            command_exit();
        } else if (!strcmp(label, "open")) {
            
        } else if (!strcmp(label, "close")) {
            
        } else if (!strcmp(label, "myactions") || !strcmp(label, "ma")) {
            
        } else if (!strcmp(label, "mybids") || !strcmp(label, "mb")) {
            
        } else if (!strcmp(label, "list") || !strcmp(label, "l")) {
            
        } else if (!strcmp(label, "show_asset") || !strcmp(label, "sa")) {
            
        } else if (!strcmp(label, "bid")) {
            
        } else if (!strcmp(label, "show_record")) {
            
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

    command_listener();
    return 1;
}