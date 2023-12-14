#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>

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
#include "database.h"

/* Auction Protocol */
#include "auction.h"

/* Misc */
#include "utils.h"

/* Roadmap (server.c) 
- test asset related functions
- implement verbose mode
- implement fork
- verify if user is already logged in when trying to log in - done?
- verify if passwords match in every command where the users sends it:
    - login
    - logout
    - unregister
    - open
    - close
    - bid
- (maybe) validate read info
*/

#define DEBUG 1
#define BACKLOG 10

#define PORT_FLAG "-p"
#define VERB_FLAG "-v"

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

#define BUFSIZ_S 256
#define BUFSIZ_M 2048
#define BUFSIZ_L 6144

int verbose = 0;

/* ---- Next Auction ID */
int next_aid = 1;

/* ---- Responses ---- */

void response_login(int fd, char *uid, char* pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        if (send(fd, "RLI ERR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
        return;
    }

    int ret = find_user_dir(uid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
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
        if (send(fd, "RLI REG\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        int ret2 = find_password(uid);
        int ret3 = find_login(uid);
        if (ret3 == ERROR) {
            printf("ERROR\n");
            return;
        } else if (ret3 == SUCCESS) {
            if (send(fd, "RLI NOK\n", 8, 0) == -1) {
                printf("ERROR\n");
                return;
            }
        } else if (ret3 == NOT_FOUND) {
            if (ret2 == NOT_FOUND) {
                create_password(uid, pwd);
                create_login(uid);
                if (send(fd, "RLI REG\n", 8, 0) == -1) {
                    printf("ERROR\n");
                    return;
                }
                return;
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
                return;
            } else if (ret2 == SUCCESS) {
                char ext_pwd[USER_PWD_LEN];
                extract_password(uid, ext_pwd);
                if (!strcmp(pwd, ext_pwd)) {
                    create_login(uid);
                    if (send(fd, "RLI OK\n", 7, 0) == -1) {
                        printf("ERROR\n");
                        return;
                    }
                } else {
                    if (send(fd, "RLI NOK\n", 8, 0) == -1) {
                        printf("ERROR\n");
                        return;
                    }
                }
            }
        }
    }
}

void response_logout(int fd, char *uid, char *pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        if (send(fd, "RLI ERR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_user_dir(uid);
    if (ret == NOT_FOUND) {
        if (send(fd, "RLO UNR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        // é necessário verificar se as passwords são iguais?
        char ext_pwd[USER_PWD_LEN];
        extract_password(uid, ext_pwd);
        if (!strcmp(pwd, ext_pwd)) {
            int ret2 = find_login(uid);
            if (ret2 == SUCCESS) {
                erase_login(uid);
                if (send(fd, "RLO OK\n", 7, 0) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == NOT_FOUND) {
                if (send(fd, "RLO NOK\n", 8, 0) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
            }
        } else {
            if (send(fd, "RLO ERR\n", 8, 0) == -1) {
                printf("ERROR\n");
                return;
            }
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    }
}

void response_unregister(int fd, char *uid, char *pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        if (send(fd, "RUR ERR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_user_dir(uid);
    if (ret == NOT_FOUND) {
        if (send(fd, "RUR UNR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        // é necessário verificar se as passwords são iguais?
        // talvez verificar primeiro se está logged in e só depois se as passes são iguais
        char ext_pwd[USER_PWD_LEN];
        extract_password(uid, ext_pwd);
        if (!strcmp(pwd, ext_pwd)) {
            int ret2 = find_login(uid);
            if (ret2 == SUCCESS) {
                erase_password(uid);
                erase_login(uid);
                if (send(fd, "RUR OK\n", 7, 0) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == NOT_FOUND) {
                if (send(fd, "RUR NOK\n", 8, 0) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
            }
        } else {
            if (send(fd, "RUR ERR\n", 8, 0) == -1) {
                printf("ERROR\n");
                return;
            }
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    }
}

void response_open(int fd, char *msg, ssize_t received) {
    // Message: OPA <uid> <password> <name> <start_value> <timeactive> <fname> <fzise> <fdata>
    char *uid = msg + 4;

    char *pwd = strchr(uid, ' ');
    *pwd++ = '\0';

    char *name = strchr(pwd, ' ');
    *name++ = '\0';

    char *start_value = strchr(name, ' ');
    *start_value++ = '\0';

    char *timeactive = strchr(start_value, ' ');
    *timeactive++ = '\0';

    char *fname = strchr(timeactive, ' ');
    *fname++ = '\0';

    char *fsize = strchr(fname, ' ');
    *fsize++ = '\0';

    char *first_bytes = strchr(fsize, ' ');
    *first_bytes++ = '\0';

    if (!validate_user_id(uid) || !validate_user_password(pwd) ||
     !validate_auction_name(name) || !validate_auction_value(start_value) ||
     !validate_auction_duration(timeactive) || !validate_file_name(fname) ||
     !validate_file_size(fsize)) {
        if (write(fd, "ROA ERR\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_login(uid);
    if (ret == NOT_FOUND) {
        if (write(fd, "ROA NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    } else if (ret == SUCCESS) {
        create_auction_dir(next_aid);
        create_start_file(next_aid, uid, name, fname, start_value, timeactive);
        add_user_auction(next_aid, uid);

        ssize_t remaining = atol(fsize);
        ssize_t to_write = (msg + received) - first_bytes;
        to_write = (remaining > to_write) ? to_write : remaining;
        create_asset_file(next_aid, fd, fname, atol(fsize), first_bytes, to_write);

        char buffer[BUFSIZ_S];
        int printed;
        if ((printed = sprintf(buffer, "ROA OK %03d\n", next_aid)) == -1) {
            printf("ERROR in sprintf\n");
            return;
        }
        if (write(fd, buffer, printed) == -1) {
            printf("ERROR\n");
            return;
        }
        next_aid++;
    }
    // quando é que retornaria ROA NOK?
}

void response_close(int fd, char *msg) {
    // Message: CLS <uid> <password> <aid>
    char *uid = msg + 4;

    char *pwd = strchr(uid, ' ');
    *pwd++ = '\0';

    char *aid = strchr(pwd, ' ');
    *aid++ = '\0';

    char *end = strchr(aid, '\n');
    *(end) = '\0';

    if (!validate_user_id(uid) || !validate_user_password(pwd) || !validate_auction_id(aid)) {
        if (write(fd, "ROA ERR\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_login(uid);
    int ret2 = find_auction(aid);
    int ret3 = find_user_auction(uid, aid);

    if (ret == ERROR || ret2 == ERROR || ret3 == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (write(fd, "RCL NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS && ret2 == NOT_FOUND) {
        if (write(fd, "RCL EAU\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS && ret2 == SUCCESS && ret3 == NOT_FOUND) {
        if (write(fd, "RCL EOW\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS && ret2 == SUCCESS && ret3 == SUCCESS && check_auction_state(aid) == CLOSED) {
        if (write(fd, "RCL END\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS && ret2 == SUCCESS && ret3 == SUCCESS && check_auction_state(aid) == OPEN) {
        time_t curr_fulltime;
        time(&curr_fulltime);
        create_end_file(aid, curr_fulltime);

        if (write(fd, "RCL OK\n", 7) == -1) {
            printf("ERROR\n");
            return;
        }
    }

}

void response_myauctions(int fd, char *uid) {
    if (!validate_user_id(uid)) {
        if (send(fd, "RMA ERR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_login(uid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (send(fd, "RMA NLG\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char auctions[BUFSIZ_L];
        memset(auctions, 0, BUFSIZ_L);
        int count = extract_user_auctions(uid, auctions);
        if (!count) {
            if (send(fd, "RMA NOK\n", 8, 0) == -1) {
                printf("ERROR\n");
                return;
            }
        } else {
            char buffer[BUFSIZ_L+8];
            memset(buffer, 0, BUFSIZ_L+8);
            sprintf(buffer, "RMA OK%s\n", auctions);
            if (send(fd, buffer, strlen(buffer), 0) == -1) {
                printf("ERROR4\n");
                return;
            }
        }

    }
}

void response_mybids(int fd, char *uid) {
    if (!validate_user_id(uid)) {
        if (send(fd, "RMB ERR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_login(uid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (send(fd, "RMB NLG\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char auctions[BUFSIZ_L];
        memset(auctions, 0, BUFSIZ_L);
        int count = extract_user_bidded_auctions(uid, auctions);
        if (!count) {
            if (send(fd, "RMB NOK\n", 8, 0) == -1) {
                printf("ERROR\n");
                return;
            }
        } else {
            char buffer[BUFSIZ_L+8];
            memset(buffer, 0, BUFSIZ_L+8);
            sprintf(buffer, "RMB OK%s\n", auctions);
            if (send(fd, buffer, strlen(buffer), 0) == -1) {
                printf("ERROR4\n");
                return;
            }
        }

    }
}

void response_list(int fd) {
    char auctions[BUFSIZ_L];
    memset(auctions, 0, BUFSIZ_L);
    int count = extract_auctions(auctions);
    if (!count) {
        if (send(fd, "RLS NOK\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else {
        char buffer[BUFSIZ_L+8];
        memset(buffer, 0, BUFSIZ_L+8);
        sprintf(buffer, "RLS OK%s\n", auctions);
        if (send(fd, buffer, strlen(buffer), 0) == -1) {
            printf("ERROR4\n");
            return;
        }
    }
}

void response_show_asset(int fd, char *msg) {
    // Message: SAS <aid>
    char *aid = msg + 4;
    *(aid + AUCTION_ID_LEN) = '\0';

    if (!validate_auction_id(aid)) {
        if (write(fd, "RSA ERR\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_auction(aid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (write(fd, "RSA NOK\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char fname[FILE_NAME_MAX_LEN+1];
        off_t fsize = 0;
        get_asset_file_info(aid, fname, &fsize);
        send_asset_file(fd, fname, fsize);

        if (write(fd, "RSA OK\n", 7) == -1) {
            printf("ERROR\n");
            return;
        }
    }

}

void response_bid(int fd, char *msg) {
    // Message: BID <uid> <password> <aid> <value>
    char *uid = msg + 4;

    char *pwd = strchr(uid, ' ');
    *pwd++ = '\0';

    char *aid = strchr(pwd, ' ');
    *aid++ = '\0';

    char *value_str = strchr(aid, ' ');
    *value_str++ = '\0';

    char *end = strchr(value_str, '\n');
    *(end) = '\0';

    if (!validate_user_id(uid) || !validate_user_password(pwd) ||
     !validate_auction_id(aid) || !validate_auction_value(value_str)) {
        if (write(fd, "RBD ERR\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    long value = atol(value_str);

    int ret = find_login(uid);
    int ret2 = find_auction(aid);

    if (ret == ERROR || ret2 == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (write(fd, "RBD NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret2 == NOT_FOUND) {
        if (write(fd, "RBD NOK\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else { // a partir sabemos que o cliente está logged in e o auction existe
        int ret3 = find_user_auction(uid, aid);
        if (ret3 == ERROR) {
            printf("ERROR\n");
            return;
        } else if (ret3 == SUCCESS) {
            if (write(fd, "RBD ILG\n", 8) == -1) {
                printf("ERROR\n");
                return;
            }
        } else { // a partir daqui sabemos que o auction não pertence ao cliente
            if (check_auction_state(aid) == CLOSED) {
                if (write(fd, "RBD NOK\n", 8) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else { // a partir daqui sabemos que o auction está aberto
                if (value <= get_max_bid_value(aid)) {
                    if (write(fd, "RBD REF\n", 8) == -1) {
                        printf("ERROR\n");
                        return;
                    }
                } else { // bid aceite
                    if (write(fd, "RBD ACC\n", 8) == -1) {
                        printf("ERROR\n");
                        return;
                    }
                    add_bid(uid, aid, value);
                    add_bidded(uid, aid);
                }
            }
        }
    }
}

void response_show_record(int fd, char *aid) {
    ssize_t total_printed = 0, printed = 0;
    
    if (!validate_auction_id(aid)) {
        if (send(fd, "RRC ERR\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_auction(aid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (send(fd, "RRC NOK\n", 8, 0) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char buffer[BUFSIZ_L];

        start_info_t start_info;
        extract_auction_start_info(aid, &start_info);
        printed = sprintf(buffer+total_printed, "RRC OK %s %s %s %s %s %s %s", start_info.uid, start_info.name,
            start_info.fname, start_info.value, start_info.date, start_info.time, start_info.timeactive);
        total_printed += printed;

        bid_info_t bids[50];
        int n_bids = extract_auctions_bids_info(aid, bids);
        for (int i = 0; i < n_bids; i++) {
            printed = sprintf(buffer+total_printed, " B %s %s %s %s %s",
                bids[i].uid, bids[i].value, bids[i].date, bids[i].time, bids[i].sec_time);
            total_printed += printed;
        }

        if (check_auction_state(aid) == CLOSED) {
            end_info_t end_info;
            extract_auction_end_info(aid, &end_info);
            printed = sprintf(buffer+total_printed, " E %s %s %s\n", end_info.date, end_info.time, end_info.sec_time);
        }

        printf("buffer: %s", buffer);
        if (send(fd, buffer, strlen(buffer), 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }
}

/* ---- Client Listener ---- */

void extract_label(char *command, char *label, int n) {
    for (int i = 1; (i < n) && (*command != ' ') && (*command != '\n'); i++) {
        *(label++) = *(command++);
    }

    *label = '\0';
}

void print_verbose(char *uid, char *type, struct sockaddr *addr, socklen_t addrlen) {
    char host[BUFSIZ_S];
    char serv[BUFSIZ_S];
    if (getnameinfo(addr, addrlen, host, BUFSIZ_S, serv, BUFSIZ_S, NI_NUMERICSERV | NI_NUMERICSERV) == -1) {
        return;
    }

    printf("[Verbose] Received %s from address %s:%s", type, host, serv);
    
    if (uid) {
        printf(" (user %s)\n", uid);
    } else {
        printf("\n");
    }
}

void tcp_command_choser(int fd) {
    char buffer[BUFSIZ_L];
    memset(buffer, 0, BUFSIZ_L);
    ssize_t received = read(fd, buffer, BUFSIZ_L);
    if (received == -1) {
        perror("read");
        return;
    }
    
    if (startswith("OPA", buffer) == 3) {
        response_open(fd, buffer, received);
    } else if (startswith("CLS", buffer) == 3) {
        response_close(fd, buffer);
    } else if (startswith("SAS", buffer) == 3) {
        response_show_asset(fd, buffer);
    } else if (startswith("BID", buffer) == 3) {
        response_bid(fd, buffer);
    } else {
        write_all_bytes(fd, "ERR\n", 4);
    }
}

void udp_command_choser(int fd) {
    struct sockaddr client_addr;
    client_addr.sa_family = AF_UNSPEC;
    socklen_t client_addrlen = sizeof(client_addr);

    char buffer[BUFSIZ_S];
    ssize_t received = recvfrom(fd, buffer, BUFSIZ_S, 0, &client_addr, &client_addrlen);
    if (received == -1) {
        perror("recvfrom");
        return;
    }

    printf("[UDP] Received %ld bytes.\n", received);

    if (connect(fd, &client_addr, client_addrlen) == -1) {
        perror("connect");
        return;
    }

    if (!validate_protocol_message(buffer, received)) {
        send(fd, "ERR\n", 4, 0);
        return;
    }

    buffer[received-1] = '\0';
    
    char *delim = " \n";
    char *label = strtok(buffer,delim);
    if (!label) {
        send(fd, "ERR\n", 4, 0);
        return;
    }
    
    if (!strcmp(label, "LIN")) {
        char *uid = strtok(NULL, delim);
        char *pwd = strtok(NULL, delim);
        if (verbose) print_verbose(uid, label, &client_addr, client_addrlen);
        response_login(fd, uid, pwd);
    } else if (!strcmp(label, "LOU")) {
        char *uid = strtok(NULL, delim);
        char *pwd = strtok(NULL, delim);
        if (verbose) print_verbose(uid, label, &client_addr, client_addrlen);
        response_logout(fd, uid, pwd);
    } else if (!strcmp(label, "UNR")) {
        char *uid = strtok(NULL, delim);
        char *pwd = strtok(NULL, delim);
        if (verbose) print_verbose(uid, label, &client_addr, client_addrlen);
        response_unregister(fd, uid, pwd);
    } else if (!strcmp(label, "LMA")) {
        char *uid = strtok(NULL, delim);
        if (verbose) print_verbose(uid, label, &client_addr, client_addrlen);
        response_myauctions(fd, uid); 
    } else if (!strcmp(label, "LMB")) {
        char *uid = strtok(NULL, delim);
        if (verbose) print_verbose(uid, label, &client_addr, client_addrlen);
        response_mybids(fd, uid);
    } else if (!strcmp(label, "LST")) {
        if (verbose) print_verbose(NULL, label, &client_addr, client_addrlen);
        response_list(fd);
    } else if (!strcmp(label, "SRC")) {
        char *aid = strtok(NULL, delim);
        if (verbose) print_verbose(NULL, label, &client_addr, client_addrlen);
        response_show_record(fd, aid);
    } else {
        if (verbose) print_verbose(NULL, label, &client_addr, client_addrlen);
        send(fd, "ERR\n", 4, 0);
    }
}

void client_listener(struct sockaddr *server_addr, socklen_t server_addrlen) {
    int fd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_udp == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (bind(fd_udp, server_addr, server_addrlen) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    
    int fd_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_tcp == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (bind(fd_tcp, server_addr, server_addrlen) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(fd_tcp, BACKLOG) == -1) {
        exit(EXIT_FAILURE);
    }

    fd_set rfds;
    while (1) {
        FD_ZERO(&rfds);
        FD_SET(fd_udp, &rfds);
        FD_SET(fd_tcp, &rfds);

        if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) == -1) {
            perror("select");
            break;
        }

        if (FD_ISSET(fd_tcp, &rfds)) {
            int new_fd = accept(fd_tcp, NULL, NULL);
            if (new_fd == -1) {
                perror("accept");
                break;
            }

            tcp_command_choser(new_fd);
        }

        if (FD_ISSET(fd_udp, &rfds)) {
            udp_command_choser(fd_udp);
        }
    }

    close(fd_udp);
    close(fd_tcp);

}

/* ---- Initialization ---- */

int main(int argc, char **argv) {
    struct sockaddr_in server_addr_in;

    server_addr_in.sin_family = AF_INET;
    server_addr_in.sin_port = htons(DEFAULT_PORT);
    server_addr_in.sin_addr.s_addr = inet_addr(DEFAULT_IP);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], VERB_FLAG)) {
            verbose = 1;
        } else if (!strcmp(argv[i], PORT_FLAG)) {
            server_addr_in.sin_port = htons(atoi(argv[++i]));
        } else {
            printf("tu es estupido vai po crl");
            exit(EXIT_FAILURE);
        }
    }

    if ((mkdir("AUCTIONS", S_IRWXU) == -1) && (errno != EEXIST)) {
        exit(EXIT_FAILURE);
    }

    if ((mkdir("USERS", S_IRWXU) == -1) && (errno != EEXIST)) {
        exit(EXIT_FAILURE);
    }

    next_aid = update_next_aid();
    client_listener((struct sockaddr*) &server_addr_in, sizeof(server_addr_in));
}