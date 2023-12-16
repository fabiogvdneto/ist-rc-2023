#define _POSIX_C_SOURCE 200809L // struct sigaction, SA_RESTART

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Networking */
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

/* Signals */
#include <signal.h>

/* Files */
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Auction Protocol */
#include "auction.h"

/* Misc */
#include "utils.h"

#define INVALID_PROTOCOL_MSG "Received invalid message from auction server.\n"
#define INVALID_USER_ID "The ID must be a 6-digit IST student number.\n"
#define INVALID_USER_PWD "The password must be composed of 8 alphanumeric characters.\n"
#define INVALID_AUCTION_ID "The AID must be a 3-digit number.\n"
#define INVALID_AUCTION_NAME "The auction name must be composed of up to 10 alphanumeric characters.\n"
#define INVALID_AUCTION_VALUE "The auction start value must be composed of up to 6 digits.\n"
#define INVALID_AUCTION_DURATION "The auction duration must be composed of up to 5 digits.\n"
#define INVALID_ASSET_NAME \
    "The asset name must be composed of up to 24 alphanumeric characters plus '_', '-' and '.'.\n"
#define INVALID_DATE "The date must be in the format YYYY-MM-DD.\n"
#define INVALID_TIME "The time must be in the format HH:MM:SS.\n"
#define ASSET_FILE_NOT_FOUND "The asset file could not be found.\n"

#define DEBUG 1

#define FLAG_PORT "-p"
#define FLAG_IP "-n"

#define DEFAULT_PORT 58011 // 58019
#define DEFAULT_IP "193.136.138.142" // "127.0.0.1"

#define BUFSIZ_S 256
#define BUFSIZ_M 2048
#define BUFSIZ_L 6144

struct sockaddr* server_addr;
socklen_t server_addrlen;

char user_uid[USER_ID_LEN+1];
char user_pwd[USER_PWD_LEN+1];

int islogged = 0;

/* ---- Sockets ---- */

struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };

int socket_connect(int type) {
    int fd = socket(AF_INET, type, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    if (connect(fd, server_addr, server_addrlen) == -1) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

int tcp_connect() {
    return socket_connect(SOCK_STREAM);
}

int udp_connect() {
    return socket_connect(SOCK_DGRAM);
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

    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "LIN %s %s\n", temp_uid, temp_pwd);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, buffer, printed, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = recv(serverfd, buffer, BUFSIZ_S, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RLI NOK\n", buffer) == received) {
        printf("Incorrect login attempt.\n");
    } else if (startswith("RLI OK\n", buffer) == received) {
        printf("Successful login.\n");
        islogged = 1;
    } else if (startswith("RLI REG\n", buffer) == received) {
        printf("New user registered.\n");
        islogged = 1;
    } else if (startswith("RLI ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
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

    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "LOU %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }
    
    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, buffer, printed, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = recv(serverfd, buffer, BUFSIZ_S, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RLO OK\n", buffer) == received) {
        printf("Successful logout.\n");
        memset(user_uid, 0, USER_ID_LEN);
        memset(user_pwd, 0, USER_PWD_LEN);
        islogged = 0;
    } else if (startswith("RLO NOK\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (startswith("RLO UNR\n", buffer) == received) {
        printf("Unknown user.\n");
    } else if (startswith("RLO ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
}

/* unregister */
void command_unregister() {
    if (!islogged) {
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }
    
    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "UNR %s %s\n", user_uid, user_pwd);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, buffer, printed, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = recv(serverfd, buffer, BUFSIZ_S, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }
    
    close(serverfd);

    if (startswith("RUR OK\n", buffer) == received) {
        printf("Successful unregister.\n");
        memset(user_uid, 0, USER_ID_LEN);
        memset(user_pwd, 0, USER_PWD_LEN);
        islogged = 0;
    } else if (startswith("RUR NOK\n", buffer) == received) {
        printf("Unknown user.\n");
    } else if (startswith("RUR UNR\n", buffer) == received) {
        printf("Incorrect unregister attempt.\n");
    } else if (startswith("RUR ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
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

    if (!validate_file_name(fname)) {
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

    char buffer[BUFSIZ_S];
    if (sprintf(buffer, "assets/%s", fname) < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int fd = open(buffer, O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT) {
            printf(ASSET_FILE_NOT_FOUND);
        } else {
            printf(ERROR_OPEN);
        }
        return;
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        close(fd);
        printf(ERROR_FSTAT);
        return;
    }

    off_t fsize = statbuf.st_size;
    void *fdata = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fdata == MAP_FAILED) {
        close(fd);
        printf(ERROR_MMAP);
        return;
    }

    close(fd);

    int printed = sprintf(buffer, "OPA %s %s %s %s %s %s %ld ",
                    user_uid, user_pwd, name, start_value, duration, fname, fsize);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = tcp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (write_all_bytes(serverfd, buffer, printed) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    if (write_all_bytes(serverfd, fdata, fsize) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    if (munmap(fdata, fsize) == -1) {
        close(serverfd);
        printf(ERROR_MMAP);
        return;
    }
    
    if (write_all_bytes(serverfd, "\n", 1) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = read_all_bytes(serverfd, buffer, BUFSIZ_S);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("ROA OK ", buffer) == 7) {
        if (!validate_protocol_message(buffer, received)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        buffer[received-1] = '\0';
        char *aid = buffer+7;
        if (!validate_auction_id(aid)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        printf("New auction opened with ID: %s.\n", aid);
    } else if (startswith("ROA NOK\n", buffer) == received) {
        printf("Auction could not be started.\n");
    } else if (startswith("ROA NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (startswith("ROA ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
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

    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "CLS %s %s %s\n", user_uid, user_pwd, aid);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = tcp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (write_all_bytes(serverfd, buffer, printed) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = read_all_bytes(serverfd, buffer, BUFSIZ_S);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RCL OK\n", buffer) == received) {
        printf("Auction was successfully closed.\n");
    } else if (startswith("RCL NLG\n", buffer) == received) {
        printf("You need to login first.\n");
    } else if (startswith("RCL EAU\n", buffer) == received) {
        printf("Auction not found.\n");
    } else if (startswith("RCL EOW\n", buffer) == received) {
        printf("You do not own that auction.\n");
    } else if (startswith("RCL END\n", buffer) == received) {
        printf("The auction %s has already ended.\n", aid);
    } else if (startswith("RCL ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
}

/* myauctions OR ma */
void command_myauctions() {
    if (!islogged) {
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "LMA %s\n", user_uid);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, buffer, printed, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = recv(serverfd, buffer, BUFSIZ_S, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RMA NOK\n", buffer) == received) {
        printf("The user %s has no ongoing auctions.\n", user_uid);
    } else if (startswith("RMA NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (startswith("RMA OK ", buffer) == 7) {
        if (!validate_protocol_message(buffer, received)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        buffer[received-1] = '\0';
        char *delim = " ";
        char *aid[BUFSIZ_S];
        char *state[BUFSIZ_S];
        int nauctions = 0;

        strtok(buffer+4, delim);
        while ((aid[nauctions] = strtok(NULL, delim))) {
            state[nauctions] = strtok(NULL, delim);

            if (!validate_auction_id(aid[nauctions]) || !validate_auction_state(state[nauctions])) {
                printf(INVALID_PROTOCOL_MSG);
                return;
            }

            nauctions++;
        }

        if (!nauctions) {
            printf("You have not started any auction yet.\n");
            return;
        }

        printf("%-10s\t%-10s\n", "Auction ID", "State");

        for (int i = 0; i < nauctions; i++) {
            printf("%-10s\t%-10s\n", aid[i], ((*state[i] == '1') ? "Active" : "Inactive"));
        }
    } else if (startswith("RMA ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
}

/* mybids OR mb */
void command_mybids() {
    if (!islogged) {
        printf(ERROR_NOT_LOGGED_IN);
        return;
    }

    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "LMB %s\n", user_uid);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, buffer, printed, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = recv(serverfd, buffer, BUFSIZ_S, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RMB NOK\n", buffer) == received) {
        printf("The user %s has no ongoing bids.\n", user_uid);
    } else if (startswith("RMB NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (startswith("RMB OK ", buffer) == 7) {
        if (!validate_protocol_message(buffer, received)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        buffer[received-1] = '\0';
        char *delim = " ";
        char *aid[BUFSIZ_S];
        char *state[BUFSIZ_S];
        int nbids = 0;

        strtok(buffer+4, delim);
        while ((aid[nbids] = strtok(NULL, delim))) {
            state[nbids] = strtok(NULL, delim);

            if (!validate_auction_id(aid[nbids]) || !validate_auction_state(state[nbids])) {
                printf(INVALID_PROTOCOL_MSG);
                return;
            }

            nbids++;
        }

        if (!nbids) {
            printf("You have not placed any bid yet.\n");
            return;
        }

        printf("%-10s\t%-10s\n", "Auction ID", "State");

        for (int i = 0; i < nbids; i++) {
            printf("%-10s\t%-10s\n", aid[i], ((*state[i] == '1') ? "Active" : "Inactive"));
        }
    } else if (startswith("RMB ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
}

/* list OR l */
void command_list() {
    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, "LST\n", 4, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    char buffer[BUFSIZ_L];
    ssize_t received = recv(serverfd, buffer, BUFSIZ_L, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RLS NOK\n", buffer) == received) {
        printf("No auction was started yet.\n");
    } else if (startswith("RLS OK ", buffer) == 7) {
        if (!validate_protocol_message(buffer, received)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        buffer[received-1] = '\0';
        char *delim = " \n";
        char *aid[1024];
        char *state[1024];
        int count = 0;

        strtok(buffer+4, delim);

        while ((aid[count] = strtok(NULL, delim))) {
            state[count] = strtok(NULL, delim);

            if (!validate_auction_id(aid[count])) {
                printf(INVALID_PROTOCOL_MSG);
                return;
            }

            if (!validate_auction_state(state[count])) {
                printf(INVALID_PROTOCOL_MSG);
                return;
            }

            count++;
        }

        if (count == 0) {
            printf("No action was created yet.");
            return;
        }

        printf("List of auctions:\n");
        printf("%-10s\t%-10s\n", "Auction ID", "State");

        for (int i = 0; i < count; i++) {
            printf("%-10s\t%-10s\n", aid[i], ((*state[i] == '1') ? "Active" : "Inactive"));
        }
    } else if (startswith("RLS ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
}

/* show_asset <aid> OR sa <aid> */
void command_show_asset(char *aid) {
    if (!validate_auction_id(aid)) {
        printf(INVALID_AUCTION_ID);
        return;
    }

    char buffer[BUFSIZ_L];
    int printed = sprintf(buffer, "SAS %s\n", aid);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = tcp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (write_all_bytes(serverfd, buffer, printed) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = read_all_bytes(serverfd, buffer, BUFSIZ_L);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    if (startswith("RSA NOK\n", buffer) == received) {
        printf("No file to be sent or error ocurred.\n");
    } else if (startswith("RSA OK ", buffer) == 7) {
        // Message: RSA OK <fname> <fsize> <fdata>
        char *fname = buffer + 7;
        
        char *fsize = strchr(fname, ' ');
        if (!fsize) {
            printf("For some unknown reason, we did not receive the file size.\n");
            close(serverfd);
            return;
        }
        *fsize++ = '\0';
        off_t fsize_value = atol(fsize);

        char *fdata = strchr(fsize, ' ');
        if (!fdata) {
            printf("For some unknown reason, we did not receive the file data.\n");
            close(serverfd);
            return;
        }
        *fdata++ = '\0';

        if (!validate_file_name(fname)) {
            close(serverfd);
            printf("%s\n", fname);
            printf("Received invalid asset name from auction server.\n");
            return;
        }

        if (!validate_file_size(fsize)) {
            close(serverfd);
            printf("Received invalid file size from auction server.\n");
            return;
        }

        if ((mkdir("output", S_IRWXU) == -1) && (errno != EEXIST)) {
            close(serverfd);
            printf(ERROR_MKDIR);
            return;
        }

        char pathname[BUFSIZ_S] = "output";
        if (sprintf(pathname, "output/%s", fname) < 0) {
            close(serverfd);
            printf(ERROR_SPRINTF);
            return;
        }

        int fd = open(pathname, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU);
        if (fd == -1) {
            close(serverfd);
            printf(ERROR_OPEN);
            return;
        }

        ssize_t remaining = fsize_value;
        ssize_t to_write = (buffer + received) - fdata;

        to_write = (remaining > to_write) ? to_write : remaining;

        ssize_t written = write_all_bytes(fd, fdata, to_write);
        if (written == -1) {
            close(serverfd);
            close(fd);
            printf(ERROR_SEND_MSG);
            return;
        }

        while (remaining -= written) {
            to_write = (remaining > BUFSIZ_L) ? BUFSIZ_L : remaining;
            to_write = read_all_bytes(serverfd, buffer, to_write);
            if (to_write == -1) {
                close(serverfd);
                close(fd);
                printf(ERROR_RECV_MSG);
                return;
            }

            if (to_write == 0) {
                close(serverfd);
                close(fd);
                printf(INVALID_PROTOCOL_MSG);
                return;
            }

            if ((written = write_all_bytes(fd, buffer, to_write)) == -1) {
                close(serverfd);
                close(fd);
                printf(ERROR_SEND_MSG);
                return;
            }
        }

        if ((received = read_all_bytes(serverfd, buffer, BUFSIZ_S)) == -1) {
            printf(ERROR_RECV_MSG);
            return;
        }

        if ((received != 1) || (*buffer != '\n')) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }
        
        close(fd);
        close(serverfd);
        printf("Download complete: %s, %ld bytes.\n", pathname, fsize_value);
    } else if (startswith("RSA ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }

    close(serverfd);
}

/* bid <aid> <value> OR b <aid> <value> */
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

    char buffer[BUFSIZ_S];
    int printed = sprintf(buffer, "BID %s %s %s %s\n", user_uid, user_pwd, aid, value);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = tcp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (write_all_bytes(serverfd, buffer, printed) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }
    
    ssize_t received = read_all_bytes(serverfd, buffer, BUFSIZ_S);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RBD NOK\n", buffer) == received) {
        printf("Auction not active.\n");
    } else if (startswith("RBD NGL\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (startswith("RBD ACC\n", buffer) == received) {
        printf("Bid accepted.\n");
    } else if (startswith("RBD REF\n", buffer) == received) {
        printf("Bid refused: value too low.\n");
    } else if (startswith("RBD ILG\n", buffer) == received) {
        printf("That auction is hosted by you.\n");
    } else if (startswith("RBD ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }

}

/* show_record <aid> OR sr <aid> */
void command_show_record(char *aid) {
    if (!validate_auction_id(aid)) {
        printf(INVALID_AUCTION_ID);
        return;
    }

    char buffer[BUFSIZ_L];
    int printed = sprintf(buffer, "SRC %s\n", aid);
    if (printed < 0) {
        printf(ERROR_SPRINTF);
        return;
    }

    int serverfd = udp_connect();
    if (serverfd == -1) {
        printf(ERROR_SOCKET);
        return;
    }

    if (send(serverfd, buffer, printed, 0) == -1) {
        close(serverfd);
        printf(ERROR_SEND_MSG);
        return;
    }

    ssize_t received = recv(serverfd, buffer, BUFSIZ_L, 0);
    if (received == -1) {
        close(serverfd);
        printf(ERROR_RECV_MSG);
        return;
    }

    close(serverfd);

    if (startswith("RRC NOK\n", buffer) == received) {
        printf("Auction doesn't exist.\n");
    } else if (startswith("RRC OK ", buffer) == 7) {
        if (!validate_protocol_message(buffer, received)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        buffer[received-1] = '\0';
        char *delim = " ";
        char *host_uid = strtok(buffer+7, delim);
        char *auction_name = strtok(NULL, delim);
        char *asset_fname = strtok(NULL, delim);
        char *start_value = strtok(NULL, delim);
        char *start_date = strtok(NULL, delim);
        char *start_time = strtok(NULL, delim);
        char *timeactive = strtok(NULL, delim);

        if (!validate_user_id(host_uid) || !validate_auction_name(auction_name) ||
                !validate_file_name(asset_fname) || !validate_auction_value(start_value) ||
                !validate_date(start_date) || !validate_time(start_time) ||
                !validate_auction_duration(timeactive)) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        char *bidder_uid[50];
        char *bid_value[50];
        char *bid_date[50];
        char *bid_time[50];
        char *bid_elapsed_time[50];
        int bid_count = 0;

        char *end_date;
        char *end_time;
        char *end_elapsed_time;
        int ended = 0;
        
        char *next;
        while ((next = strtok(NULL, delim))) {
            if (!strcmp(next, "B")) {
                bidder_uid[bid_count] = strtok(NULL, delim);
                bid_value[bid_count] = strtok(NULL, delim);
                bid_date[bid_count] = strtok(NULL, delim);
                bid_time[bid_count] = strtok(NULL, delim);
                bid_elapsed_time[bid_count] = strtok(NULL, delim);

                if (!validate_user_id(bidder_uid[bid_count]) ||
                        !validate_auction_value(bid_value[bid_count]) ||
                        !validate_date(bid_date[bid_count]) ||
                        !validate_time(bid_time[bid_count]) ||
                        !validate_elapsed_time(bid_elapsed_time[bid_count])) {
                    printf(INVALID_PROTOCOL_MSG);
                    return;
                }

                bid_count++;
            } else if (!strcmp(next, "E")) {
                end_date = strtok(NULL, delim);
                end_time = strtok(NULL, delim);
                end_elapsed_time = strtok(NULL, delim);

                if (strtok(NULL, delim) || !validate_date(end_date) || !validate_time(end_time) ||
                        !validate_elapsed_time(end_elapsed_time)) {
                    printf(INVALID_PROTOCOL_MSG);
                    return;
                }

                ended = 1;
                break;
            } else {
                printf(INVALID_PROTOCOL_MSG);
                return;
            }
        }

        printf("Auction %s:\n", aid);
        printf(" -> started by user %s on %s, %s.\n", host_uid, start_date, start_time);
        printf(" -> starting with value %s and lasting at most %s seconds.\n", start_value, timeactive);
        printf(" -> named \"%s\" with asset \"%s\".\n", auction_name, asset_fname);

        if ((!bid_count) && ended) {
            printf("No bids were placed in this auction.\n");
        } else if (!bid_count) {
            printf("No bids have been placed in this auction yet.\n");
        } else {
            printf("List of bids placed in this auction:\n");
        }
        for (int i = 0; i < bid_count; i++) {
            printf(" - Bid placed by user %s, with value %s, on %s, %s, with %s seconds elapsed.\n", 
                    bidder_uid[i], bid_value[i], bid_date[i], bid_time[i], bid_elapsed_time[i]);
        }

        if (ended) {
            printf("Ended on %s, %s, %s seconds after being started.\n", end_date, end_time, end_elapsed_time);
        }
    } else if (startswith("RRC ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (startswith("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    } else {
        printf(INVALID_PROTOCOL_MSG);
    }
}

/* help */
void command_help() {
    printf("Commands available:\n");
    printf("• login <uid> <password> | Login to server.\n");
    printf("• logout | Logout from server.\n");
    printf("• unregister | Unregister account.\n");
    printf("• exit | Exit from CLI.\n");
    printf("• open <name> <filename> <start-value> <duration> | Open a new auction.\n");
    printf("• close <auction-id> | Close ongoing auction.\n");
    printf("• myauctions | List auctions created by you.\n");
    printf("• mybids | List your bids.\n");
    printf("• list | List all auctions ever created.\n");
    printf("• show_asset <auction-id> | Show auction asset.\n");
    printf("• bid <auction id> <bid-value> | Place a bid.\n");
    printf("• show_record <auction-id> | Show info about an auction.\n");
}

/* ---- Command Listener ---- */

void command_listener() {
    char buffer[BUFSIZ_S];
    char *label, *delim = " \n";

    printf("> ");
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
            if (!islogged) return;
            printf(ERROR_EXIT_LOGGED_IN);
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
            char *aid = strtok(NULL, delim);
            command_show_record(aid);
        } else if (!strcmp("help", label)) {
            command_help();
        } else {
            printf(ERROR_COMMAND_NOT_FOUND);
        }

        printf("> ");
    }

    fprintf(stderr, ERROR_FGETS);
}

/* ---- Initialization ---- */

void stop() {
    if (islogged) {
        write(STDIN_FILENO, "\nPlease logout first.\n", 22);
        write(STDIN_FILENO, "> ", 2);
        return;
    }

    _exit(EXIT_SUCCESS);
}

void handle_signals() {
    struct sigaction act;

    // About sigaction flags:
    // https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/signal.h.html
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    act.sa_handler = SIG_IGN;

    if (sigaction(SIGPIPE, &act, NULL) == -1) {
        printf(ERROR_SIGACTION);
        exit(EXIT_FAILURE);
    }

    act.sa_handler = stop;

    if (sigaction(SIGINT, &act, NULL) == -1) {
        printf(ERROR_SIGACTION);
        exit(EXIT_FAILURE);
    }

    // SIGCHD (when child dies -> SIG_IGN)
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
    if (islogged) command_logout();
    return EXIT_SUCCESS;
}