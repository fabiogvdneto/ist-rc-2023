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
- implement function to create asset file
- implement verbose mode
- implement fork
- implement remaining responses:
    - response to show_asset command
    - response to show_record command
- verify if user is already logged in when trying to log in
*/

#define DEBUG 1

#define PORT_FLAG "-p"
#define VERB_FLAG "-v"

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

#define BUFSIZ_S 256
#define BUFSIZ_M 2048
#define BUFSIZ_L 6144

struct sockaddr* server_addr;

socklen_t server_addrlen;

int verbose = 0;

/* ---- Next Auction ID */
int next_aid = 1;

void udp_send(int fd, char *msg) {
    size_t n = strlen(msg);
    ssize_t res = sendto(fd, msg, n, 0, server_addr, server_addrlen);

    if (res == -1) {
        printf("Error: could not send message to server.\n");
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("[UDP] Sent %ld/%ld bytes: %s", res, n, msg);
}

/* ---- Responses ---- */

void response_login(int fd, char *uid, char* pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        if (sendto(fd, "RLI ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
        return;
    }

    int ret = find_user_dir(uid);
    if (ret == NOT_FOUND) {
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
        if (sendto(fd, "RLI REG\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        int ret2 = find_password(uid);
        if (ret2 == NOT_FOUND) {
            create_password(uid, pwd);
            create_login(uid);
            if (sendto(fd, "RLI REG\n", 8, 0, server_addr, server_addrlen) == -1) {
                printf("ERROR\n");
                return;
            }
            return;
        } else if (ret2 == ERROR) {
            printf("ERROR\n");
            return;
        } else if (ret2 == SUCCESS) {
            // TODO: verificar se o user já está logged in?
            char ext_pwd[USER_PWD_LEN];
            extract_password(uid, ext_pwd);
            if (!strcmp(pwd, ext_pwd)) {
                create_login(uid);
                if (sendto(fd, "RLI OK\n", 7, 0, server_addr, server_addrlen) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else {
                if (sendto(fd, "RLI NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
                    printf("ERROR\n");
                    return;
                }
            }
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    }
}

void response_logout(int fd, char *uid, char *pwd) {
    if (!validate_user_id(uid) || !validate_user_password(pwd)) {
        if (sendto(fd, "RLI ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_user_dir(uid);
    if (ret == NOT_FOUND) {
        if (sendto(fd, "RLO UNR\n", 8, 0, server_addr, server_addrlen) == -1) {
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
                if (sendto(fd, "RLO OK\n", 7, 0, server_addr, server_addrlen) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == NOT_FOUND) {
                if (sendto(fd, "RLO NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
            }
        } else {
            if (sendto(fd, "RLO ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
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
        if (sendto(fd, "RUR ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_user_dir(uid);
    if (ret == NOT_FOUND) {
        if (sendto(fd, "RUR UNR\n", 8, 0, server_addr, server_addrlen) == -1) {
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
                if (sendto(fd, "RUR OK\n", 7, 0, server_addr, server_addrlen) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == NOT_FOUND) {
                if (sendto(fd, "RUR NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
                    printf("ERROR\n");
                    return;
                }
            } else if (ret2 == ERROR) {
                printf("ERROR\n");
            }
        } else {
            if (sendto(fd, "RUR ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
                printf("ERROR\n");
                return;
            }
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    }
}

void response_open(int fd, char *msg) {
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

    char *fdata = strchr(fsize, ' ');
    *fdata++ = '\0';

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
        // TODO: call create_asset_file());
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
        if (sendto(fd, "RMA ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_login(uid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (sendto(fd, "RMA NLG\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char auctions[BUFSIZ_L];
        memset(auctions, 0, BUFSIZ_L);
        int count = extract_user_auctions(uid, auctions);
        if (!count) {
            if (sendto(fd, "RMA NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
                printf("ERROR\n");
                return;
            }
        } else {
            char buffer[BUFSIZ_L+8];
            memset(buffer, 0, BUFSIZ_L+8);
            sprintf(buffer, "RMA OK%s\n", auctions);
            if (sendto(fd, buffer, strlen(buffer), 0, server_addr, server_addrlen) == -1) {
                printf("ERROR4\n");
                return;
            }
        }

    }
}

void response_mybids(int fd, char *uid) {
    if (!validate_user_id(uid)) {
        if (sendto(fd, "RMB ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_login(uid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (sendto(fd, "RMB NLG\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char auctions[BUFSIZ_L];
        memset(auctions, 0, BUFSIZ_L);
        int count = extract_user_bidded_auctions(uid, auctions);
        if (!count) {
            if (sendto(fd, "RMB NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
                printf("ERROR\n");
                return;
            }
        } else {
            char buffer[BUFSIZ_L+8];
            memset(buffer, 0, BUFSIZ_L+8);
            sprintf(buffer, "RMB OK%s\n", auctions);
            if (sendto(fd, buffer, strlen(buffer), 0, server_addr, server_addrlen) == -1) {
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
        if (sendto(fd, "RLS NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else {
        char buffer[BUFSIZ_L+8];
        memset(buffer, 0, BUFSIZ_L+8);
        sprintf(buffer, "RLS OK%s\n", auctions);
        if (sendto(fd, buffer, strlen(buffer), 0, server_addr, server_addrlen) == -1) {
            printf("ERROR4\n");
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
    if (!validate_auction_id(aid)) {
        if (sendto(fd, "RRC ERR\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    }

    int ret = find_auction(aid);
    if (ret == ERROR) {
        printf("ERROR\n");
        return;
    } else if (ret == NOT_FOUND) {
        if (sendto(fd, "RRC NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char host_uid[USER_ID_LEN+1];
        char name[AUCTION_NAME_MAX_LEN+1];
        char fname[FILE_NAME_MAX_LEN+1];
        char start_value[AUCTION_VALUE_MAX_LEN+1];
        char start_date[DATE_LEN+1];
        char start_time[TIME_LEN+1];
        char timeactive[AUCTION_DURATION_MAX_LEN+1];
        extract_auction_start_info(aid, host_uid, name, 
            fname, start_value, start_date, start_time, timeactive);
        char buffer[BUFSIZ_L];
        sprintf(buffer, "RRC OK %s %s %s %s %s %s %s\n", host_uid, name,
            fname, start_value, start_date, start_time, timeactive);
        printf("buffer: %s\n", buffer);
        if (sendto(fd, buffer, strlen(buffer), 0, server_addr, server_addrlen) == -1) {
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

void tcp_command_choser(int fd) {
    char *label;
    char buffer[BUFSIZ_L];
    memset(buffer, 0, BUFSIZ_L);
    ssize_t received = read(fd, buffer, BUFSIZ_L);
    if (received == -1) {
        printf("ERROR: %s.\n", strerror(errno));
        return;
    }
    // TODO: fix not printing the buffer
    printf("[TCP] Received: %s", buffer);
    // TODO: validar formato da mensagem recebida
    // e enviar "ERR" se estiver errado
    label = buffer;
    *(label+3) = '\0';
    if (!strcmp(label, "OPA")) {
        response_open(fd, buffer);
    } else if (!strcmp(label, "CLS")) {
        response_close(fd, buffer);
    } else if (!strcmp(label, "SAS")) {
        udp_send(fd, "RSA OK\n");
    } else if (!strcmp(label, "BID")) {
        response_bid(fd, buffer);
    } else {
        printf("Received unreconizable message: %s\n", buffer);
    }
}

void udp_command_choser(int fd) {
    char *label, *delim = " \n";
    char buffer[BUFSIZ_S];
    memset(buffer, 0, BUFSIZ_S);
    ssize_t received = recvfrom(fd, buffer, BUFSIZ_S, 0, server_addr, &server_addrlen);
    if (received == -1) {
        printf("ERROR: %s.\n", strerror(errno));
        return;
    } 
    printf("[UDP] Received: %s", buffer);
    // TODO: validar formato da mensagem recebida
    // e enviar "ERR" se estiver errado
    if (!(label = strtok(buffer, delim))) {}
    
    if (!strcmp(label, "LIN")) {
        char *uid = strtok(NULL, delim);
        char *pwd = strtok(NULL, delim);
        response_login(fd, uid, pwd);
    } else if (!strcmp(label, "LOU")) {
        char *uid = strtok(NULL, delim);
        char *pwd = strtok(NULL, delim);
        response_logout(fd, uid, pwd);
    } else if (!strcmp(label, "UNR")) {
        char *uid = strtok(NULL, delim);
        char *pwd = strtok(NULL, delim);
        response_unregister(fd, uid, pwd);
    } else if (!strcmp(label, "LMA")) {
        char *uid = strtok(NULL, delim);
        response_myauctions(fd, uid); 
    } else if (!strcmp(label, "LMB")) {
        char *uid = strtok(NULL, delim);
        response_mybids(fd, uid);
    } else if (!strcmp(label, "LST")) {
        response_list(fd);
    } else if (!strcmp(label, "SRC")) {
        char *aid = strtok(NULL, delim);
        response_show_record(fd, aid);
    } else {
        printf("Received unreconizable message: %s\n", buffer);
    }
}

void client_listener() {
    int fd_udp = udp_socket();
    if (bind(fd_udp, server_addr, server_addrlen)) {
        exit(EXIT_FAILURE);
    }

    int fd_tcp = tcp_socket();
    if (bind(fd_tcp, server_addr, server_addrlen)) {
        exit(EXIT_FAILURE);
    }

    if (listen(fd_tcp, 1) == -1) {
        exit(EXIT_FAILURE);
    }

    fd_set rfds;
    while (1) {
        FD_ZERO(&rfds);
        FD_SET(fd_udp, &rfds);
        FD_SET(fd_tcp, &rfds);

        if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) == -1) {
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(fd_tcp, &rfds)) {
            int new_fd = accept(fd_tcp, server_addr, &server_addrlen);
            if (new_fd == -1) {
                exit(EXIT_FAILURE);
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
    server_addr = (struct sockaddr*) &server_addr_in;
    server_addrlen = sizeof(server_addr_in);

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
    client_listener();
}