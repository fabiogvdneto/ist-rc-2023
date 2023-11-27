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

/* Auction */
#include "auction.h"

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
#define BIG_BUFFER_LEN 6144
#define PACKET_SIZE 2048

struct sockaddr_in server_addr;

char user_uid[USER_UID_LEN+1];
char user_pwd[USER_PWD_LEN+1];

int islogged = 0;

void panic(char *msg) {
    fprintf(stderr, "%s", msg);
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

int str_starts_with(char *prefix, char *str) {
    while (*prefix != '\0') {
        if ((*str == '\0') || *(prefix++) != *(str++)) {
            return 0;
        }
    }

    return 1;
}

/* ---- Commands ---- */

/* login <UID> <password> */
void command_login(char *temp_uid, char *temp_pwd) {
    if (islogged) {
        printf("You are already logged in.\n");
        return;
    }

    if (!validate_user_id(temp_uid)) {
        printf("The UID must be a 6-digit IST student number.\n");
        return;
    }

    if (!validate_user_password(temp_pwd)) {
        printf("The password must be composed of 8 alphanumeric characters.\n");
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LIN %s %s\n", temp_uid, temp_pwd);
    if (printed < 0) {
        panic("sprintf() at login");
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("socket() at login");
    }

    if (udp_send(serverfd, buffer, printed, server_addr) == -1) {
        close(serverfd);
        panic("sendto() at login");
    }

    ssize_t received = udp_recv(serverfd, buffer, BUFFER_LEN, server_addr);
    if (received == -1) {
        close(serverfd);
        panic("recvfrom() at login");
    }

    close(serverfd);

    if (str_starts_with("RLI NOK\n", buffer)) {
        printf("Incorrect login attempt.\n");
    } else if (str_starts_with("RLI OK\n", buffer)) {
        printf("Successful login.\n");
        islogged = 1;
    } else if (str_starts_with("RLI REG\n", buffer)) {
        printf("New user registered.\n");
        islogged = 1;
    } else if (str_starts_with("RLI ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }

    if (islogged) {
        strcpy(user_uid, temp_uid);
        strcpy(user_pwd, temp_pwd);
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

    if (str_starts_with("RLO OK\n", buffer)) {
        printf("Successful logout.\n");
        memset(user_uid, 0, USER_UID_LEN);
        memset(user_pwd, 0, USER_PWD_LEN);
        islogged = 0;
    } else if (str_starts_with("RLO NOK\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("RLO UNR\n", buffer)) {
        printf("Unknown user.\n");
    } else if (str_starts_with("RLO ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
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
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("Error");
    }

    if (udp_send(serverfd, buffer, printed, server_addr) == -1) {
        panic("Error");
    }

    ssize_t received = udp_recv(serverfd, buffer, BUFFER_LEN, server_addr);
    if (received == -1) {
        panic("Error");
    }
    
    close(serverfd);

    if (str_starts_with("RUR OK\n", buffer)) {
        printf("Successful unregister.\n");
        islogged = 0;
    } else if (str_starts_with("RUR NOK\n", buffer)) {
        printf("Unknown user.\n");
    } else if (str_starts_with("RUR UNR\n", buffer)) {
        printf("Incorrect unregister attempt.\n");
    } else if (str_starts_with("RUR ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
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
void command_open(char *name, char *fname, char *start_value, char *duration) {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }

    if (!validate_auction_name(name)) {
        printf("The auction name must be composed of up to 10 alphanumeric characters.\n");
        return;
    }

    if (!validate_asset_name(fname)) {
        printf("The asset name must be composed of up to 24 alphanumeric characters plus '_', '-' and '.'.\n");
        return;
    }

    if (!validate_auction_value(start_value)) {
        printf("The auction start value must be composed of up to 6 digits.\n");
        return;
    }
    
    if (!validate_auction_duration(duration)) {
        printf("The auction duration must be composed of up to 5 digits.\n");
        return;
    }

    char buffer[BUFFER_LEN];
    if (sprintf(buffer, "assets/%s", fname) < 0) {
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

    int printed = sprintf(buffer, "OPA %s %s %s %s %s %s %ld ",
                    user_uid, user_pwd, name, start_value, duration, fname, fsize);
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
        close(serverfd);
        panic("Error: could not connect to server.\n");
    }

    if (tcp_send(serverfd, buffer, printed) == -1) {
        close(fd);
        close(serverfd);
        panic("Error: could not send message to server.\n");
    }

    if (tcp_send(serverfd, fdata, fsize) == -1) {
        close(fd);
        close(serverfd);
        panic("Error: could not send file data to server.\n");
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

    if (str_starts_with("ROA OK ", buffer)) {
        char aid[AID_LEN+1];

        sscanf(buffer, "ROA OK %s\n", aid);

        if (!validate_auction_id(aid)) {
            printf("Invalid AID was returned.\n");
            return;
        }

        printf("New auction opened: %s.\n", aid);
    } else if (str_starts_with("ROA NOK\n", buffer)) {
        printf("Auction could not be started.\n");
    } else if (str_starts_with("ROA NLG\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("ROA ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }
}

void command_bid(char *aid, char *value) {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }

    if (!validate_auction_id(aid)) {
        printf("The AID must be a 3-digit number.\n");
        return;
    }

    if (!validate_auction_value(value)) {
        printf("The bid value must be composed of up to 6 digits.\n");
        return;
    }

    char buffer[BUFFER_LEN];
    int printed = sprintf(buffer, "BID %s %s %s %s\n", user_uid, user_pwd, aid, value);
    if (printed < 0) {
        panic("Error: sprintf().\n");
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        panic("Error: socket().\n");
    }

    if (tcp_conn(serverfd, server_addr) == -1) {
        close(serverfd);
        panic("Error: could not connect to server.\n");
    }

    if (tcp_send(serverfd, buffer, printed) == -1) {
        close(serverfd);
        panic("Error: could not send message to server.\n");
    }

    ssize_t received = tcp_recv(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic("Error: could not receive message from server.\n");
    }

    close(serverfd);

    if (str_starts_with("RBD NOK\n", buffer)) {
        printf("Auction not active.\n");
    } else if (str_starts_with("RBD NGL\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("RBD ACC\n", buffer)) {
        printf("Bid accepted.\n");
    } else if (str_starts_with("RBD REF\n", buffer)) {
        printf("Bid refused: a larger a bid has already been placed.\n");
    } else if (str_starts_with("RBD ILG\n", buffer)) {
        printf("That auction is hosted by you.\n");
    } else if (str_starts_with("ROA ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }

}

/* close <AID> */
void command_close(char *aid) {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }

    if (!validate_auction_id(aid)) {
        printf("The auction ID must be composed of 3 digits.\n");
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "CLS %s %s %s\n", user_uid, user_pwd, aid);
    if (printed < 0) {
        panic("sprintf() at login");
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        panic("Error: socket().\n");
    }

    if (tcp_conn(serverfd, server_addr) == -1) {
        close(serverfd);
        panic("Error: could not connect to server.\n");
    }

    if (tcp_send(serverfd, buffer, printed) == -1) {
        close(serverfd);
        panic("Error: could not send message to server.\n");
    }

    ssize_t received = tcp_recv(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic("Error: could not receive message from server.\n");
    }

    close(serverfd);

    if (str_starts_with("RCL OK\n", buffer)) {
        printf("Auction was successfully closed.\n");
    } else if (str_starts_with("RCL NLG\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("RCL EAU\n", buffer)) {
        printf("The auction %s doesn't exist.\n", aid);
    } else if (str_starts_with("RCL EOW\n", buffer)) {
        printf("The auction %s is not owned by the user %s.\n", aid, user_uid);
    } else if (str_starts_with("RCL END\n", buffer)) {
        printf("The auction %s has already ended.\n", aid);
    } else if (str_starts_with("RCL ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }
}

/* myauctions OR ma */
void command_myauctions() {
    if (!islogged) {
        printf("User not logged in.\n");
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LMA %s\n", user_uid);
    if (printed < 0) {
        panic("sprintf() at login");
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("Error: socket().\n");
    }

    if (udp_send(serverfd, buffer, printed, server_addr) == -1) {
        panic("Error");
    }

    ssize_t received = udp_recv(serverfd, buffer, BUFFER_LEN, server_addr);
    if (received == -1) {
        panic("Error");
    }

    close(serverfd);

    if (str_starts_with("RMA NOK\n", buffer)) {
        printf("The user %s has no ongoing auctions.\n", user_uid);
    } else if (str_starts_with("RMA NLG\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("RMA OK ", buffer)) {
        printf("List of auctions owned by user %s:\n", user_uid);

        char aid[AID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic("Error: sscanf().\n");
            }

            printf("Auction %s: %s.\n", aid, (status ? "active" : "inactive"));
        }
    } else if (str_starts_with("RMA ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }
}

/* list OR l */
void command_list() {
    char buffer[BIG_BUFFER_LEN];

    int printed = sprintf(buffer, "LST\n");
    if (printed < 0) {
        panic("sprintf() at login");
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic("Error: socket().\n");
    }

    if (udp_send(serverfd, buffer, printed, server_addr) == -1) {
        panic("Error");
    }

    ssize_t received = udp_recv(serverfd, buffer, BIG_BUFFER_LEN, server_addr);
    if (received == -1) {
        panic("Error");
    }

    close(serverfd);

    if (str_starts_with("RLS NOK\n", buffer)) {
        printf("No auction was started yet.\n");
    } else if (str_starts_with("RLS OK ", buffer)) {
        printf("List of ongoing auctions:\n");
        // TODO: fix this loop (iteratively read from socket)
        char aid[AID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic("Error: sscanf().\n");
            } 

            if (status) {
                printf("Auction %s.\n", aid);
            }
        }
    } else if (str_starts_with("RLS ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }
}

/* ---- Command Listener ---- */

void command_listener() {
    char buffer[BUFFER_LEN];
    char *delim = " \n";

    while (fgets(buffer, sizeof(buffer), stdin)) {
        char *label = strtok(buffer, delim);

        if (!strcmp("login", label)) {
            char *uid = strtok(NULL, delim);
            char *pwd = strtok(NULL, delim);

            if (!pwd) {
                printf("Usage: login <user id> <password>\n");
                continue;
            }

            command_login(uid, pwd);
        } else if (!strcmp("logout", label)) {
            command_logout();
        } else if (!strcmp("unregister", label)) {
            command_unregister();
        } else if (!strcmp("exit", label)) {
            command_exit();
        } else if (!strcmp("open", label)) {
            char *name = strtok(NULL, delim);
            char *fname = strtok(NULL, delim);
            char *value = strtok(NULL, delim);
            char *duration = strtok(NULL, delim);

            if (!duration) {
                printf("Usage: open <short description> <filename> <start value> <duration>\n");
                continue;
            }

            command_open(name, fname, value, duration);
        } else if (!strcmp("close", label)) {
            char *aid = strtok(NULL, delim);

            if (!aid) {
                printf("Usage: close <auction id>\n");
                continue;
            }

            command_close(aid);
        } else if (!strcmp("myactions", label) || !strcmp("ma", label)) {
            command_myauctions();
        } else if (!strcmp("mybids", label) || !strcmp("mb", label)) {
            
        } else if (!strcmp("list", label) || !strcmp("l", label)) {
            command_list();
        } else if (!strcmp("show_asset", label) || !strcmp("sa", label)) {
            
        } else if (!strcmp("bid", label) || !strcmp("b", label)) {
            char *aid = strtok(NULL, delim);
            char *value = strtok(NULL, delim);

            if (!value) {
                printf("Usage: bid <auction id> <bid>\n");
                continue;
            }
            
            command_bid(aid, value);
        } else if (!strcmp("show_record", label)) {
            
        } else {
            printf("Command not found.\n");
        }
    }

    panic("Error: could not read from stdin.\n");
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