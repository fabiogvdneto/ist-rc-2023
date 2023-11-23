#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

/* Signals */
#include <signal.h>

/* Files */
#include <sys/mman.h>
#include <fcntl.h>

/* TODOs

- select()
- Timers (setsockopt()).
- Signals (SIGSEGV, SIGINT ctrl-c, SIGCHLD server-side, SIGPIPE).
- Um processo para cada cliente.
- Create some tests

*/

/* tejo.tecnico.ulisboa.pt (193.136.138.142:58011)

Command: ./user -n 193.136.138.142 -p 58011

*/

#define DEBUG 1

#define FLAG_PORT "-p"
#define FLAG_IP "-n"

#define DEFAULT_PORT 58011 // 58019
#define DEFAULT_IP "193.136.138.142" // "127.0.0.1"

#define BUFFER_LEN 128
#define PACKET_SIZE 2048

#define USER_UID_LEN 6
#define USER_PWD_LEN 8
#define AUCTION_NAME_LEN 10
#define ASSET_FNAME_LEN 24
#define STARTVALUE_LEN 6
#define DURATION_LEN 5
#define AID_LEN 3

struct sockaddr_in server_addr;

char user_uid[USER_UID_LEN+1];
char user_pwd[USER_PWD_LEN+1];

int islogged = 0;

void panic(char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

/* ---- UDP Protocol ---- */

int udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

ssize_t udp_send(int sockfd, char *buffer, size_t nbytes, struct sockaddr_in addr) {
    return sendto(sockfd, buffer, nbytes, 0, (struct sockaddr*) &addr, sizeof(addr));
}

ssize_t udp_recv(int sockfd, char *buffer, size_t nbytes, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    return recvfrom(sockfd, buffer, nbytes, 0, (struct sockaddr*) &addr, &addrlen);
}

/* ---- TCP Protocol ---- */

int tcp_socket() {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int tcp_conn(int sockfd, struct sockaddr_in addr) {
    return connect(sockfd, (struct sockaddr*) &addr, sizeof(addr));
}

ssize_t tcp_send(int sockfd, char *buffer, ssize_t nbytes) {
    return write(sockfd, buffer, nbytes);
}

ssize_t tcp_recv(int sockfd, char *buffer, ssize_t nbytes) {
    return read(sockfd, buffer, nbytes);
}

/* ---- Validators ---- */

int starts_with(char *prefix, char *str) {
    while (*prefix != '\0') {
        if ((*str == '\0') || *(prefix++) != *(str++)) {
            return 0;
        }
    }

    return 1;
}

int validate_user_uid(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i == USER_UID_LEN);
}

int validate_password(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }

    return (i == USER_PWD_LEN);
}

int validate_auction_name(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }

    return (i <= AUCTION_NAME_LEN);
}

int validate_startvalue(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i <= STARTVALUE_LEN);
}

int validate_duration(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i <= DURATION_LEN);
}

int validate_AID(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i == AID_LEN);
}

/* ---- Commands ---- */

/* login <UID> <password> */
void command_login(char *command) {
    char temp_uid[BUFFER_LEN];
    char temp_pwd[BUFFER_LEN];
    
    if (sscanf(command, "login %s %s\n", temp_uid, temp_pwd) < 0) {
        panic("Error");
    }
    
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

    int printed = sprintf(buffer, "LIN %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        panic("sprintf() at login");
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("socket() at login");
    }

    ssize_t sent = udp_send(serverfd, buffer, printed, server_addr);
    if (sent == -1) {
        close(serverfd);
        panic("sendto() at login");
    }

    ssize_t received = udp_recv(serverfd, buffer, BUFFER_LEN, server_addr);
    if (received == -1) {
        close(serverfd);
        panic("recvfrom() at login");
    }

    close(serverfd);

    if (!strncmp(buffer, "RLI NOK\n", received)) {
        printf("Incorrect login attempt.\n");
    } else if (!strncmp(buffer, "RLI OK\n", received)) {
        printf("Successfull login.\n");
        islogged = 1;
    } else if (!strncmp(buffer, "RLI REG\n", received)) {
        printf("New user registered.\n");
        islogged = 1;
    }
}

/* logout */
void command_logout() {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LOU %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        panic("Error");
    }
    
    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("Error");
    }

    if (udp_send(serverfd, buffer, printed, server_addr) == -1) {
        close(serverfd);
        panic("Error");
    }

    ssize_t received = udp_recv(serverfd, buffer, BUFFER_LEN, server_addr);
    if (received == -1) {
        close(serverfd);
        panic("Error");
    }

    close(serverfd);

    if (!strncmp(buffer, "RLO OK\n", received)) {
        printf("Successfull logout.\n");
        islogged = 0;
    } else if (!strncmp(buffer, "RLO NOK\n", received)) {
        printf("User not logged in.\n");
    } else if (!strncmp(buffer, "RLO UNR\n", received)) {
        printf("Unknown user.\n");
    }
}

/* unregister */
void command_unregister() {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }
    
    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "UNR %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        panic("Error");
        exit(EXIT_FAILURE);
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("Error");
        exit(EXIT_FAILURE);
    }

    ssize_t sent = udp_send(serverfd, buffer, printed, server_addr);
    if (sent == -1) {
        panic("Error");
        exit(EXIT_FAILURE);
    }

    ssize_t received = udp_recv(serverfd, buffer, BUFFER_LEN, server_addr);
    if (received == -1) {
        panic("Error");
        exit(EXIT_FAILURE);
    }
    
    close(serverfd);

    if (!strncmp(buffer, "RUR OK\n", received)) {
        printf("Successfull unregister.\n");
        islogged = 0;
    } else if (!strncmp(buffer, "RUR NOK\n", received)) {
        printf("Unknown user.\n");
    } else if (!strncmp(buffer, "RUR UNR\n", received)) {
        printf("Incorrect unregister attempt.\n");
    }
}

/* exit */
void command_exit() {
    if (islogged) {
        printf("You need to logout first.\n");
        return;
    }

    exit(EXIT_SUCCESS);
}

/* open <name> <asset_fname> <start_value> <timeactive> */
void command_open(char *command) {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }
    
    char name[AUCTION_NAME_LEN+1];
    char asset_fname[ASSET_FNAME_LEN+1];
    char start_value[STARTVALUE_LEN+1];
    char timeactive[DURATION_LEN+1];
    
    if (sscanf(command, "open %s %s %s %s\n", name, asset_fname, start_value, timeactive) < 0) {
        panic("Error: sscanf().\n");
    }

    if (!validate_auction_name(name)) {
        printf("The auction name must be composed of up to 10 alphanumeric characters.\n");
        return;
    }

    // validate asset fname ...

    if (!validate_startvalue(start_value)) {
        printf("The auction start value must be composed of up to 6 digits.\n");
        return;
    }
    
    if (!validate_duration(timeactive)) {
        printf("The auction duration must be composed of up to 5 digits.\n");
        return;
    }

    char buffer[BUFFER_LEN];
    if (sprintf(buffer, "assets/%s", asset_fname) < 0) {
        panic("Error: sprintf().\n");
    }

    int fd = open(buffer, O_RDONLY);
    if (fd == -1) {
        panic("Error: open().\n");
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        close(fd);
        panic("Error: fstat().\n");
    }

    off_t fsize = statbuf.st_size;
    void *fdata = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fdata == MAP_FAILED) {
        close(fd);
        panic("Error: mmap().\n");
    }

    int printed = sprintf(buffer, "OPA %s %s %s %s %s %s %ld ", user_uid, user_pwd,
                                name, start_value, timeactive, asset_fname, fsize);
    if (printed < 0) {
        close(fd);
        panic("Error: sprintf().\n");
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        close(fd);
        panic("Error: socket().\n");
    }

    if (tcp_conn(serverfd, server_addr) == -1) {
        close(fd);
        panic("Error: could not connect to server.\n");
    }

    ssize_t sent = tcp_send(serverfd, buffer, printed);
    if (sent == -1) {
        close(fd);
        close(serverfd);
        panic("Error: could not send message to server.\n");
    }

    for (ssize_t count = 0; count < fsize; count += sent) {
        ssize_t nbytes = (fsize - count) > PACKET_SIZE ? PACKET_SIZE : (fsize - count);

        sent = tcp_send(serverfd, (fdata + count), nbytes);
        if (sent == -1) {
            close(fd);
            close(serverfd);
            perror("Error");
            fprintf(stderr, "Error: could not send file packet to server (sent %ld/%ld Bytes).\n", count, fsize);
            exit(EXIT_FAILURE);
        }
    }

    if (munmap(fdata, fsize) == -1) {
        close(fd);
        close(serverfd);
        panic("Error: munmap().\n");
    }
    
    close(fd);
    
    if (tcp_send(serverfd, "\n", 1) == -1) {
        close(serverfd);
        panic("Error: could not send break line to server.\n");
    }

    ssize_t received = tcp_recv(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic("Error: could not receive message from server.\n");
    }

    close(serverfd);

    if (starts_with("ROA OK ", buffer)) {
        char AID[AID_LEN+1];

        sscanf(buffer, "ROA OK %s\n", AID);

        if (!validate_AID(AID)) {
            printf("Got successfull response but invalid AID.\n");
            return;
        }

        printf("New action opened: %s.\n", AID);
    } else if (!strncmp(buffer, "ROA NOK\n", received)) {
        printf("Auction could not be started.\n");
    } else if (!strncmp(buffer, "RUR NLG\n", received)) {
        printf("User not logged in.\n");
    }
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
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            panic("Error: could not read from stdin.\n");
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
            command_open(buffer);
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

void handle_signals() {
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;

    if (sigaction(SIGPIPE, &act, NULL) == -1) {
        panic("Error: could not modify signal behaviour.");
    }
}

int main(int argc, char **argv) {
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(DEFAULT_IP);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], FLAG_IP)) {
            server_addr.sin_addr.s_addr = inet_addr(argv[++i]);
        } else if (!strcmp(argv[i], FLAG_PORT)) {
            server_addr.sin_port = htons(atoi(argv[++i]));
        } else {
            printf("A sua pessoa apresenta-se néscia, encaminhe-se no sentido do orgão genital masculino.\n");
            exit(EXIT_FAILURE);
        }
    }

    handle_signals();
    command_listener();
    return 1;
}