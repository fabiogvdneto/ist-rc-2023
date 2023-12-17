#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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
- implement verbose mode in TCP
- implement fork
- overview:
    - send <3letters> ERR when database functions return ERROR
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

void response_login(int fd, char *uid, char *pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        send(fd, "RLI ERR\n", 8, 0);
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
                char ext_pwd[USER_PWD_LEN+1];
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
        char ext_pwd[USER_PWD_LEN+1];
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
        char ext_pwd[USER_PWD_LEN+1];
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
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (write(fd, "RCL NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char ext_pwd[USER_PWD_LEN+1];
        extract_password(uid, ext_pwd);
        if (strcmp(pwd, ext_pwd)) {
            if (write(fd, "RCL ERR\n", 8) == -1) {
                printf("ERROR\n");
                return;
            }
        } else {
            int ret2 = find_auction(aid);
            if (ret2 == ERROR) {
                printf("ERROR\n");
                return;
            } else if (ret2 == NOT_FOUND) {
                if (write(fd, "RCL EAU\n", 8) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == SUCCESS) {
                int ret3 = find_user_auction(uid, aid);
                if (ret3 == ERROR) {
                    printf("ERROR\n");
                    return;
                } else if (ret3 == NOT_FOUND) {
                    if (write(fd, "RCL EOW\n", 8) == -1) {
                        printf("ERROR\n");
                        return;
                    }
                } else if (ret3 == SUCCESS) {
                    int state = check_auction_state(aid);
                    if (state == ERROR) {
                        printf("ERROR\n");
                        return;
                    } else if (state == CLOSED) {
                        if (write(fd, "RCL END\n", 8) == -1) {
                            printf("ERROR\n");
                            return;
                        }
                    } else if (state == OPEN) {
                        time_t curr_fulltime;
                        time(&curr_fulltime);
                        create_end_file(aid, curr_fulltime);

                        if (write(fd, "RCL OK\n", 7) == -1) {
                            printf("ERROR\n");
                            return;
                        }
                    }
                    
                }
            }
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
        char buffer[BUFSIZ_S];
        ssize_t printed = sprintf(buffer, "RSA OK %s %ld ", fname, fsize);
        if (write(fd, buffer, printed) == -1) {
            printf("ERROR\n");
            return;
        }
        send_asset_file(fd, aid, fname, fsize);
        if (write(fd, "\n", 1) == -1) {
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
        char ext_pwd[USER_PWD_LEN+1];
        extract_password(uid, ext_pwd);
        if (strcmp(pwd, ext_pwd)) {
            if (write(fd, "RBD ERR\n", 8) == -1) {
                printf("ERROR\n");
                return;
            }
        }
        
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
        memset(buffer, 0, BUFSIZ_L);

        start_info_t start_info;
        extract_auction_start_info(aid, &start_info);
        printed = sprintf(buffer, "RRC OK %s %s %s %s %s %s %s", start_info.uid, start_info.name,
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
            printed = sprintf(buffer+total_printed, " E %s %s %s", end_info.date, end_info.time, end_info.sec_time);
            total_printed += printed;
        }
        buffer[total_printed] = '\n';
        
        if (send(fd, buffer, strlen(buffer), 0) == -1) {
            printf("ERROR\n");
            return;
        }
    }
}

/* ---- Client Listener ---- */

void print_verbose(char *uid, char *type, struct sockaddr *addr, socklen_t addrlen) {
    if (!verbose)
        return;

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
    char buffer[BUFSIZ_L+1];
    ssize_t received = read_all_bytes(fd, buffer, BUFSIZ_L);
    if (received == -1) {
        perror("read");
        return;
    }
    buffer[received] = '\0';
    char *ptr = buffer;
    char *delim = " ";

    char *request = strsep(&ptr, delim);
    
    if (!strcmp(request, "OPA")) {
        char *uid = strsep(&ptr, delim);
        char *pwd = strsep(&ptr, delim);
        char *name = strsep(&ptr, delim);
        char *start_value = strsep(&ptr, delim);
        char *timeactive = strsep(&ptr, delim);
        char *fname = strsep(&ptr, delim);
        char *fsize = strsep(&ptr, delim);
        char *fdata = ptr;

        if (!validate_user_id(uid) || !validate_user_password(pwd) ||
                !validate_auction_name(name) || !validate_auction_value(start_value) ||
                !validate_auction_duration(timeactive) || !validate_file_name(fname) ||
                !validate_file_size(fsize) || (ptr == NULL) || (ptr - buffer > received)) {
            write_all_bytes(fd, "ROA ERR\n", 4);
            return;
        }

        FILE *file = fopen(fname, "w");
        if (!file) {
            printf(ERROR_OPEN);
            return;
        }

        received = (buffer + received) - fdata;

        ssize_t remaining = atoi(fsize);
        ssize_t to_write = (remaining < received) ? remaining : received;
        if (fwrite(fdata, 1, to_write, file) < (size_t) to_write) {
            fclose(file);
            printf(ERROR_SEND_MSG);
            return;
        }

        if ((remaining -= to_write) > 0) {
            remaining = read_file_data(fd, file, remaining);
            fclose(file);
            if (remaining > 0) {
                write_all_bytes(fd, "ROA ERR\n", 4);
                return;
            }

            if (remaining == -1) {
                printf("An error occured while transferring data from socket to file.\n");
                return;
            }

            received = read(fd, buffer, BUFSIZ_S);
            if (received == -1) {
                printf(ERROR_RECV_MSG);
                remove(fname);
                return;
            }

            fdata = buffer;
        } else {
            fclose(file);
            fdata += to_write;
            received -= to_write;
        }

        if (received != 1) {
            write_all_bytes(fd, "ROA ERR\n", 4);
            remove(fname);
            return;
        }

        if (*fdata != '\n') {
            write_all_bytes(fd, "ROA ERR\n", 4);
            remove(fname);
            return;
        }

        start_info_t auction;
        strcpy(auction.uid, uid);
        strcpy(auction.name, name);
        strcpy(auction.value, start_value);
        strcpy(auction.timeactive, timeactive);
        strcpy(auction.fname, fname);
        
        int aid = create_auction(pwd, &auction);

        if (aid > 0) {
            int printed = sprintf(buffer, "ROA OK %03d\n", aid);
            write_all_bytes(fd, buffer, printed);
        } else if (aid == USER_NOT_LOGGED_IN) {
            write_all_bytes(fd, "ROA NLG\n", 8);
        } else {
            write_all_bytes(fd, "ROA NOK\n", 8);
        }
    } else if (!strcmp(request, "CLS")) {
        char *uid = strsep(&ptr, delim);
        char *pwd = strsep(&ptr, delim);
        char *aid = strsep(&ptr, "\n");
        
        if ((*ptr != '\0') || !validate_user_id(uid) || !validate_user_password(pwd) ||
                !validate_auction_id(aid)) {
            write_all_bytes(fd, "ERR\n", 4);
            return;
        }

        response_close(fd, buffer);
    } else if (!strcmp(request, "SAS")) {
        char *aid = strsep(&ptr, "\n");
        
        if ((*ptr != '\0') || !validate_auction_id(aid)) {
            write_all_bytes(fd, "ERR\n", 4);
            return;
        }

        response_show_asset(fd, buffer);
    } else if (!strcmp(request, "BID")) {
        char *uid = strsep(&ptr, delim);
        char *pwd = strsep(&ptr, delim);
        char *aid = strsep(&ptr, delim);
        char *value = strsep(&ptr, "\n");
        
        if ((*ptr != '\0') || !validate_user_id(uid) || !validate_user_password(pwd) ||
                !validate_auction_id(aid) || !validate_auction_value(value)) {
            write_all_bytes(fd, "ERR\n", 4);
            return;
        }

        response_bid(fd, buffer);
    } else {
        write_all_bytes(fd, "ERR\n", 4);
    }
}

void udp_command_choser(int fd) {
    struct sockaddr client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

    char buffer[BUFSIZ_S];
    ssize_t received = recvfrom(fd, buffer, BUFSIZ_S, 0, &client_addr, &client_addrlen);
    if (received == -1) {
        perror("recvfrom");
        return;
    }

    if (connect(fd, &client_addr, client_addrlen) == -1) {
        perror("connect");
        return;
    }

    if (!validate_protocol_message(buffer, received)) {
        send(fd, "ERR\n", 4, 0);
        return;
    }
    
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

    client_addr.sa_family = AF_UNSPEC;
    if (connect(fd, &client_addr, client_addrlen) == -1) {
        perror("connect");
        return;
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
        perror("listen");
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