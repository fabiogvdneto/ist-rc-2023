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

#define ERROR_ALREADY_LOGGED_IN "You are already logged in."
#define ERROR_NOT_LOGGED_IN "You need to login first."
#define ERROR_EXIT_LOGGED_IN "You need to logout first."
#define ERROR_SOCKET "[Error] Could not create socket."
#define ERROR_MMAP "[Error] Failed to map file into memory."
#define ERROR_MUNMAP "[Error] Failed to unmap file from memory."
#define ERROR_SEND_MSG "[Error] Could not send message to server."
#define ERROR_RECV_MSG "[Error] Could not receive message from server."
#define ERROR_CONNECT "[Error] Could not establish connection with server."
#define ERROR_SPRINTF "[Error] sprintf()."
#define ERROR_SSCANF "[Error]"
#define ERROR_OPEN "[Error] Failed to open file."
#define ERROR_FSTAT "[Error] Failed to get file attributes."
#define ERROR_FGETS "[Error] Could not read from stdin."
#define ERROR_SIGACTION "[Error] Could not modify signal behaviour."

#define INVALID_USER_ID "The ID must be a 6-digit IST student number."
#define INVALID_USER_PWD "The password must be composed of 8 alphanumeric characters."
#define INVALID_AUCTION_ID "The AID must be a 3-digit number."
#define INVALID_AUCTION_NAME "The auction name must be composed of up to 10 alphanumeric characters."
#define INVALID_AUCTION_VALUE "The auction start value must be composed of up to 6 digits."
#define INVALID_AUCTION_DURATION "The auction duration must be composed of up to 5 digits."
#define INVALID_ASSET_NAME \
    "The asset name must be composed of up to 24 alphanumeric characters plus '_', '-' and '.'."

#define DEBUG 1

#define FLAG_PORT "-p"
#define FLAG_IP "-n"

#define DEFAULT_PORT 58011 // 58019
#define DEFAULT_IP "193.136.138.142" // "127.0.0.1"

#define BUFFER_LEN 128
#define BIG_BUFFER_LEN 6144
#define PACKET_SIZE 2048

struct sockaddr* server_addr;

socklen_t server_addrlen;

char user_uid[USER_ID_LEN+1];
char user_pwd[USER_PWD_LEN+1];

int islogged = 0;

void panic(char *str) {
    fprintf(stderr, "%s\n", str);
    exit(EXIT_FAILURE);
}

/* ---- Sockets ---- */

int udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

int tcp_socket() {
    return socket(AF_INET, SOCK_STREAM, 0);
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
        printf(ERROR_ALREADY_LOGGED_IN);
        return;
    }

    if (!validate_user_id(temp_uid)) {
        printf(INVALID_USER_ID);
        return;
    }

    if (!validate_user_password(temp_pwd)) {
        printf(INVALID_USER_PWD);
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LIN %s %s\n", temp_uid, temp_pwd);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (sendto(serverfd, buffer, printed, 0, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
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
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LOU %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }
    
    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (sendto(serverfd, buffer, printed, 0, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (str_starts_with("RLO OK\n", buffer)) {
        printf("Successful logout.\n");
        memset(user_uid, 0, USER_ID_LEN);
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
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }
    
    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "UNR %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (sendto(serverfd, buffer, printed, 0, server_addr, server_addrlen) == -1) {
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        panic(ERROR_RECV_MSG);
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
        fprintf(stderr, ERROR_EXIT_LOGGED_IN);
        return;
    }

    exit(EXIT_SUCCESS);
}

/* open <name> <asset_fname> <start_value> <timeactive> */
void command_open(char *name, char *fname, char *start_value, char *duration) {
    if (!islogged) {
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    if (!validate_auction_name(name)) {
        printf(INVALID_AUCTION_NAME);
        return;
    }

    if (!validate_asset_name(fname)) {
        printf(INVALID_ASSET_NAME);
        return;
    }

    if (!validate_auction_value(start_value)) {
        printf(INVALID_AUCTION_VALUE);
        return;
    }
    
    if (!validate_auction_duration(duration)) {
        printf(INVALID_AUCTION_DURATION);
        return;
    }

    char buffer[BUFFER_LEN];
    if (sprintf(buffer, "assets/%s", fname) < 0) {
        panic(ERROR_SPRINTF);
    }

    int fd = open(buffer, O_RDONLY);
    if (fd == -1) {
        panic(ERROR_OPEN);
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        close(fd);
        panic(ERROR_FSTAT);
    }

    off_t fsize = statbuf.st_size;
    void *fdata = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fdata == MAP_FAILED) {
        close(fd);
        panic(ERROR_MMAP);
    }

    close(fd);

    int printed = sprintf(buffer, "OPA %s %s %s %s %s %s %ld ",
                    user_uid, user_pwd, name, start_value, duration, fname, fsize);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (connect(serverfd, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_CONNECT);
        exit(EXIT_FAILURE);
    }

    if (write(serverfd, buffer, printed) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    if (write(serverfd, fdata, fsize) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    if (munmap(fdata, fsize) == -1) {
        close(serverfd);
        panic(ERROR_MMAP);
    }
    
    if (write(serverfd, "\n", 1) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = read(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (str_starts_with("ROA OK ", buffer)) {
        char aid[AUCTION_ID_LEN+1];

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

/* bid <aid> <value> */
void command_bid(char *aid, char *value) {
    if (!islogged) {
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    if (!validate_auction_id(aid)) {
        printf(INVALID_AUCTION_ID);
        return;
    }

    if (!validate_auction_value(value)) {
        printf(INVALID_AUCTION_VALUE);
        return;
    }

    char buffer[BUFFER_LEN];
    int printed = sprintf(buffer, "BID %s %s %s %s\n", user_uid, user_pwd, aid, value);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (connect(serverfd, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_CONNECT);
    }

    if (write(serverfd, buffer, printed) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = read(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
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
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    if (!validate_auction_id(aid)) {
        printf(INVALID_AUCTION_ID);
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "CLS %s %s %s\n", user_uid, user_pwd, aid);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (connect(serverfd, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_CONNECT);
    }

    if (write(serverfd, buffer, printed) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = read(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
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
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LMA %s\n", user_uid);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (sendto(serverfd, buffer, printed, 0, server_addr, server_addrlen) == -1) {
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (str_starts_with("RMA NOK\n", buffer)) {
        printf("The user %s has no ongoing auctions.\n", user_uid);
    } else if (str_starts_with("RMA NLG\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("RMA OK ", buffer)) {
        printf("List of auctions owned by user %s:\n", user_uid);

        char aid[AUCTION_ID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic(ERROR_SSCANF);
            }

            printf("Auction %s: %s.\n", aid, (status ? "active" : "inactive"));
        }
    } else if (str_starts_with("RMA ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }
}

/* mybids OR mb */
void command_mybids() {
    if (!islogged) {
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    char buffer[BUFFER_LEN];

    int printed = sprintf(buffer, "LMB %s\n", user_uid);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (sendto(serverfd, buffer, printed, 0, server_addr, server_addrlen) == -1) {
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (str_starts_with("RMB NOK\n", buffer)) {
        printf("The user %s has no ongoing bids.\n", user_uid);
    } else if (str_starts_with("RMB NLG\n", buffer)) {
        printf("User not logged in.\n");
    } else if (str_starts_with("RMB OK ", buffer)) {
        printf("List of auctions for which user %s has placed bids:\n", user_uid);

        char aid[AUCTION_ID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic(ERROR_SSCANF);
            }

            printf("Auction %s: %s.\n", aid, (status ? "active" : "inactive"));
        }
    } else if (str_starts_with("RMB ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }
}

/* list OR l */
void command_list() {
    int serverfd = udp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (sendto(serverfd, "LST\n", 4, 0, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    char buffer[BIG_BUFFER_LEN];
    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (str_starts_with("RLS NOK\n", buffer)) {
        printf("No auction was started yet.\n");
    } else if (str_starts_with("RLS OK ", buffer)) {
        printf("List of ongoing auctions:\n");
        char aid[AUCTION_ID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic(ERROR_SSCANF);
            }

            if (!validate_auction_id(aid)) {
                printf("The auction ID must be composed of 3 digits.\n");
                return;
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

/* show_asset <aid> OR sa <aid>*/
void command_show_asset(char *aid) {
    if (!validate_auction_id(aid)) {
        printf(INVALID_AUCTION_ID);
        return;
    }

    char buffer[BUFFER_LEN];
    int printed = sprintf(buffer, "SAS %s\n", aid);
    if (printed < 0) {
        panic(ERROR_SPRINTF);
    }

    int serverfd = tcp_socket();
    if (serverfd == -1) {
        panic(ERROR_SOCKET);
    }

    if (connect(serverfd, server_addr, server_addrlen) == -1) {
        close(serverfd);
        panic(ERROR_CONNECT);
    }

    if (write(serverfd, buffer, printed) == -1) {
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = read(serverfd, buffer, BUFFER_LEN);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    if (str_starts_with("RSA NOK\n", buffer)) {
        printf("No file to be sent or error ocurred.\n");
    } else if (str_starts_with("RSA OK ", buffer)) {
        char fname[FILENAME_LEN];
        char fdata[BUFFER_LEN];
        off_t fsize;

        if (sscanf(buffer, "RSA OK %s %ld", fname, &fsize) < 0) {
            // TODO: fix bug where sscanf fails
            close(serverfd);
            panic(ERROR_SSCANF);
        }

        if (!validate_asset_name(fname)) {
            close(serverfd);
            printf(INVALID_ASSET_NAME);
            return;
        }

        /* char path[BUFFER_LEN];
        if (sprintf(path, "received_assets/%s", fname) < 0) {
            close(serverfd);
            panic("Error: sprintf().\n");
        } */

        int fd = open(fname, O_CREAT|O_WRONLY|O_TRUNC, 00770); // user and group can write, read and execute
        if (fd == -1) {
            close(serverfd);
            printf("%s\n", strerror(errno));
            panic(ERROR_OPEN);
        }

        // TODO: implement loop to read from socket and write to file
        ssize_t count = 0;
        while (count < fsize) {
            ssize_t written = write(fd, fdata + count, fsize);
            if (written == -1) {
                close(serverfd);
                close(fd);
                panic("Error: write.\n");
            }
            printf("debug\n");

            count += written;
        }

        close(fd);
    } else if (str_starts_with("RSA ERR\n", buffer)) {
        printf("Received error message.\n");
    } else if (str_starts_with("ERR\n", buffer)) {
        printf("Received general error message.\n");
    }

    close(serverfd);
}

/* ---- Command Listener ---- */

void command_listener() {
    char buffer[BUFFER_LEN];
    char *label, *delim = " \n";

    while (fgets(buffer, sizeof(buffer), stdin)) {
        if (!(label = strtok(buffer, delim))) continue;

        if (!strcmp("login", label)) {
            char *uid = strtok(NULL, delim);
            char *pwd = strtok(NULL, delim);
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
            command_open(name, fname, value, duration);
        } else if (!strcmp("close", label)) {
            char *aid = strtok(NULL, delim);
            command_close(aid);
        } else if (!strcmp("myauctions", label) || !strcmp("ma", label)) {
            command_myauctions();
        } else if (!strcmp("mybids", label) || !strcmp("mb", label)) {
            command_mybids();
        } else if (!strcmp("list", label) || !strcmp("l", label)) {
            command_list();
        } else if (!strcmp("show_asset", label) || !strcmp("sa", label)) {
            char *aid = strtok(NULL, delim);
            command_show_asset(aid);
        } else if (!strcmp("bid", label) || !strcmp("b", label)) {
            char *aid = strtok(NULL, delim);
            char *value = strtok(NULL, delim);
            command_bid(aid, value);
        } else if (!strcmp("show_record", label) || !strcmp("sr", label)) {
            
        } else {
            printf("Command not found.\n");
        }
    }

    fprintf(stderr, ERROR_FGETS);
}

/* ---- Initialization ---- */

void handle_signals() {
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;

    if (sigaction(SIGPIPE, &act, NULL) == -1) {
        panic(ERROR_SIGACTION);
    }
}

int main(int argc, char **argv) {
    struct sockaddr_in server_addr_in;

    server_addr_in.sin_family = AF_INET;
    server_addr_in.sin_port = htons(DEFAULT_PORT);
    server_addr_in.sin_addr.s_addr = inet_addr(DEFAULT_IP);
    server_addr = (struct sockaddr*) &server_addr_in;
    server_addrlen = sizeof(server_addr_in);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], FLAG_IP)) {
            server_addr_in.sin_addr.s_addr = inet_addr(argv[++i]);
        } else if (!strcmp(argv[i], FLAG_PORT)) {
            server_addr_in.sin_port = htons(atoi(argv[++i]));
        } else {
            printf("A sua pessoa apresenta-se néscia, encaminhe-se no sentido do orgão genital masculino.\n");
            exit(EXIT_FAILURE);
        }
    }

    handle_signals();
    command_listener();
    return 1;
}