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

#define ERROR_ALREADY_LOGGED_IN "You are already logged in.\n"
#define ERROR_NOT_LOGGED_IN "You need to login first.\n"
#define ERROR_EXIT_LOGGED_IN "You need to logout first.\n"
#define ERROR_SOCKET "[Error] Could not create socket.\n"
#define ERROR_MMAP "[Error] Failed to map file into memory.\n"
#define ERROR_MUNMAP "[Error] Failed to unmap file from memory.\n"
#define ERROR_SEND_MSG "[Error] Could not send message to server.\n"
#define ERROR_RECV_MSG "[Error] Could not receive message from server.\n"
#define ERROR_CONNECT "[Error] Could not establish connection with server.\n"
#define ERROR_SPRINTF "[Error] sprintf().\n"
#define ERROR_SSCANF "[Error] sscanf().\n"
#define ERROR_OPEN "[Error] Failed to open file.\n"
#define ERROR_MKDIR "[Error] Failed to create directory.\n"
#define ERROR_FSTAT "[Error] Failed to get file attributes.\n"
#define ERROR_FGETS "[Error] Could not read from stdin.\n"
#define ERROR_SIGACTION "[Error] Could not modify signal behaviour.\n"

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
    fprintf(stderr, "%s", str);
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

/**
 * This fucntion is similar to strspn() builtin function, but the initial segment can only be 
 * located at the start of the string.
 * Returns the number of bytes from prefix that matches the given string.
*/
int prefixspn(char *prefix, char *str) {
    char *start = str;
    while (*prefix && (*prefix++ == *str++));
    return (str - start);
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

    if (prefixspn("RLI NOK\n", buffer) == received) {
        printf("Incorrect login attempt.\n");
    } else if (prefixspn("RLI OK\n", buffer) == received) {
        printf("Successful login.\n");
        islogged = 1;
    } else if (prefixspn("RLI REG\n", buffer) == received) {
        printf("New user registered.\n");
        islogged = 1;
    } else if (prefixspn("RLI ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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

    if (prefixspn("RLO OK\n", buffer) == received) {
        printf("Successful logout.\n");
        memset(user_uid, 0, USER_ID_LEN);
        memset(user_pwd, 0, USER_PWD_LEN);
        islogged = 0;
    } else if (prefixspn("RLO NOK\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (prefixspn("RLO UNR\n", buffer) == received) {
        printf("Unknown user.\n");
    } else if (prefixspn("RLO ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }
    
    close(serverfd);

    if (prefixspn("RUR OK\n", buffer) == received) {
        printf("Successful unregister.\n");
        memset(user_uid, 0, USER_ID_LEN);
        memset(user_pwd, 0, USER_PWD_LEN);
        islogged = 0;
    } else if (prefixspn("RUR NOK\n", buffer) == received) {
        printf("Unknown user.\n");
    } else if (prefixspn("RUR UNR\n", buffer) == received) {
        printf("Incorrect unregister attempt.\n");
    } else if (prefixspn("RUR ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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

    if (prefixspn("ROA OK ", buffer) == 7) {
        char aid[AUCTION_ID_LEN+1];

        sscanf(buffer, "ROA OK %s\n", aid);

        if (!validate_auction_id(aid)) {
            printf("Invalid AID was returned.\n");
            return;
        }

        printf("New auction opened: %s.\n", aid);
    } else if (prefixspn("ROA NOK\n", buffer) == received) {
        printf("Auction could not be started.\n");
    } else if (prefixspn("ROA NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (prefixspn("ROA ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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

    if (prefixspn("RCL OK\n", buffer) == received) {
        printf("Auction was successfully closed.\n");
    } else if (prefixspn("RCL NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (prefixspn("RCL EAU\n", buffer) == received) {
        printf("The auction %s doesn't exist.\n", aid);
    } else if (prefixspn("RCL EOW\n", buffer) == received) {
        printf("The auction %s is not owned by the user %s.\n", aid, user_uid);
    } else if (prefixspn("RCL END\n", buffer) == received) {
        printf("The auction %s has already ended.\n", aid);
    } else if (prefixspn("RCL ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (prefixspn("RMA NOK\n", buffer) == received) {
        printf("The user %s has no ongoing auctions.\n", user_uid);
    } else if (prefixspn("RMA NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (prefixspn("RMA OK ", buffer) == 7) {
        printf("List of auctions owned by user %s:\n", user_uid);

        char aid[AUCTION_ID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic(ERROR_SSCANF);
            }

            printf("Auction %s: %s.\n", aid, (status ? "active" : "inactive"));
        }
    } else if (prefixspn("RMA ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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
        close(serverfd);
        panic(ERROR_SEND_MSG);
    }

    ssize_t received = recv(serverfd, buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (prefixspn("RMB NOK\n", buffer) == received) {
        printf("The user %s has no ongoing bids.\n", user_uid);
    } else if (prefixspn("RMB NLG\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (prefixspn("RMB OK ", buffer) == 7) {
        printf("List of auctions for which user %s has placed bids:\n", user_uid);

        char aid[AUCTION_ID_LEN+1];
        int status;
        for (char *ptr = buffer + 6; *ptr != '\n'; ptr += 6) {
            if (sscanf(ptr, " %s %d", aid, &status) < 0) {
                panic(ERROR_SSCANF);
            }

            printf("Auction %s: %s.\n", aid, (status ? "active" : "inactive"));
        }
    } else if (prefixspn("RMB ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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

    if (prefixspn("RLS NOK\n", buffer) == received) {
        printf("No auction was started yet.\n");
    } else if (prefixspn("RLS OK ", buffer) == 7) {
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
    } else if (prefixspn("RLS ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
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

    if (prefixspn("RSA NOK\n", buffer) == received) {
        printf("No file to be sent or error ocurred.\n");
    } else if (prefixspn("RSA OK ", buffer) == 7) {
        char *fname = buffer + 7;
        
        char *fsize = strchr(fname, ' ');
        if (!fsize) {
            printf("For some unknown reason, we did not receive the file size.\n");
            close(serverfd);
            return;
        }
        *fsize++ = '\0';

        char *fdata = strchr(fsize, ' ');
        if (!fdata) {
            printf("For some unknown reason, we did not receive the file data.\n");
            close(serverfd);
            return;
        }
        *fdata++ = '\0';

        if (!validate_file_name(fname)) {
            close(serverfd);
            printf("Received invalid asset name from auction server.\n");
            return;
        }

        if (!validate_file_size(fsize)) {
            close(serverfd);
            printf("Received invalid file size from auction server.\n");
            return;
        }

        if (sprintf(buffer, "output/%s", fname) < 0) {
            close(serverfd);
            panic(ERROR_SPRINTF);
        }

        if (mkdir("output", S_IRWXU) == -1 && errno != EEXIST) {
            close(serverfd);
            panic(ERROR_MKDIR);
        }

        int fd = open(buffer, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU);
        if (fd == -1) {
            close(serverfd);
            panic(ERROR_OPEN);
        }

        ssize_t remaining = atol(fsize);
        ssize_t to_write = (buffer + received) - fdata;
        ssize_t written = 0;

        to_write = (remaining > to_write) ? to_write : remaining;

        while (to_write > written) {
            written += write(fd, fdata+written, to_write-written);
        }

        char packet[BIG_BUFFER_LEN];

        while (remaining -= written) {
            to_write = (remaining > BIG_BUFFER_LEN) ? BIG_BUFFER_LEN : remaining;
            to_write = read(serverfd, packet, to_write);
            if (to_write == -1) {
                close(serverfd);
                close(fd);
                panic(ERROR_RECV_MSG);
            }

            if (to_write == 0) {
                close(serverfd);
                close(fd);
                panic(INVALID_PROTOCOL_MSG);
            }

            written = 0;
            while (to_write > written) {
                written += write(fd, packet+written, to_write-written);
            }
        }

        // read '\n'?
        
        close(fd);
        close(serverfd);
        printf("Download complete: %s\n", buffer);
    } else if (prefixspn("RSA ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
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

    if (prefixspn("RBD NOK\n", buffer) == received) {
        printf("Auction not active.\n");
    } else if (prefixspn("RBD NGL\n", buffer) == received) {
        printf("User not logged in.\n");
    } else if (prefixspn("RBD ACC\n", buffer) == received) {
        printf("Bid accepted.\n");
    } else if (prefixspn("RBD REF\n", buffer) == received) {
        printf("Bid refused: a larger a bid has already been placed.\n");
    } else if (prefixspn("RBD ILG\n", buffer) == received) {
        printf("That auction is hosted by you.\n");
    } else if (prefixspn("RBD ERR\n", buffer) == received) {
        printf("Received error message.\n");
    } else if (prefixspn("ERR\n", buffer) == received) {
        printf("Received general error message.\n");
    }

}

/* show_record <aid> OR sr <aid> */
void command_show_record(char *aid) {
    if (!validate_auction_id(aid)) {
        printf(INVALID_AUCTION_ID);
        return;
    }

    char buffer[BUFFER_LEN];
    int printed = sprintf(buffer, "SRC %s\n", aid);
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

    // primeira parte da resposta - 82 bytes (3+1+2+1+6+1+10+1+24+1+6+1+19+1+5)
    // segunda parte da resposta (que se repete até 50 vezes) - 50 * (1+1+1+6+1+6+1+19+1+5)
    // terceira parte da resposta - 28 bytes (1+1+1+19+1+5)
    // total - 2210 bytes
    char big_buffer[BIG_BUFFER_LEN];
    ssize_t received = recv(serverfd, big_buffer, BUFFER_LEN, 0);
    if (received == -1) {
        close(serverfd);
        panic(ERROR_RECV_MSG);
    }

    close(serverfd);

    if (prefixspn("RRC NOK\n", big_buffer) == received) {
        printf("Auction doesn't exist.\n");
    } else if (prefixspn("RRC OK ", big_buffer) == 7) {
        
        char *ptr = buffer;

        while (*ptr != '\n') {
            if ((*ptr == ' ') && (*(ptr+1) == ' ')) {
                printf(INVALID_PROTOCOL_MSG);
                return;
            }
        }

        if ((ptr - buffer) != received) {
            printf(INVALID_PROTOCOL_MSG);
            return;
        }

        char *delim = " \n";
        char *host_uid = strtok(buffer+7, delim);
        if (!validate_user_id(host_uid)) {
            printf(INVALID_USER_ID);
            return;
        }

        char *auction_name = strtok(NULL, delim);
        if (!validate_auction_name(auction_name)) {
            printf(INVALID_AUCTION_NAME);
            return;
        }

        char *asset_fname = strtok(NULL, delim);
        if (!validate_file_name(asset_fname)) {
            printf(INVALID_ASSET_NAME);
            return;
        }

        char *start_value = strtok(NULL, delim);
        if (!validate_auction_value(start_value)) {
            printf(INVALID_AUCTION_VALUE);
            return;
        }

        char *start_date = strtok(NULL, delim);
        if (!validate_date(start_date)) {
            printf(INVALID_DATE);
            return;
        }

        char *start_time = strtok(NULL, delim);
        if (!validate_time(start_time)) {
            printf(INVALID_TIME);
            return;
        }

    }
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
    return 1;
}