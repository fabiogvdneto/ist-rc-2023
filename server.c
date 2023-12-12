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

/* Auction Protocol */
#include "auction.h"

/* Misc */
#include "utils.h"

/* Roadmap (server.c) 
- implement function to create asset file
- update global variable next_aid's value when executing the server
- implement verbose mode
- fix myauctions (stash smashed)
- implement fork
- implemente remaining responses:
    - response to my_bids command
    - response to list command
    - response to show_asset command
    - response to show_record command
- add separate files (.c and .h) to keep functions that manage the AS database
*/

#define DEBUG 1

#define PORT_FLAG "-p"
#define VERB_FLAG "-v"

#define DEFAULT_PORT 58019
#define DEFAULT_IP "127.0.0.1"

#define BUFSIZ_S 256
#define BUFSIZ_M 2048
#define BUFSIZ_L 6144

#define NON_EXIST 2
#define SUCCESS 1
#define ERROR -1

#define CLOSED 3
#define OPEN 4

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
    if (find_user_dir(uid) == NON_EXIST) {
        return NON_EXIST;
    }

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

// 2 -> não existe ficheiro de password
// 1 -> existe ficheiro de password
// 0 -> erro
int find_password(char *uid) {
    if (find_user_dir(uid) == NON_EXIST) {
        return NON_EXIST;
    }

    char password_name[40];
    FILE *fp;

    sprintf(password_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(password_name, "r")) == NULL) {
        if (errno == ENOENT) {
            return NON_EXIST;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int create_auction_dir() {
    char aid_dirname[20];
    char asset_dirname[30];
    char bids_dirname[30];

    sprintf(aid_dirname, "AUCTIONS/%03d", next_aid);
    if ((mkdir(aid_dirname, 0700)) == -1) {
        return ERROR;
    }

    sprintf(asset_dirname, "AUCTIONS/%03d/ASSET", next_aid);
    if ((mkdir(asset_dirname, 0700)) == -1) {
        rmdir(aid_dirname);
        return ERROR;
    }

    sprintf(bids_dirname, "AUCTIONS/%03d/BIDS", next_aid);
    if ((mkdir(bids_dirname, 0700)) == -1) {
        rmdir(aid_dirname);
        rmdir(asset_dirname);
        return ERROR;
    }

    return SUCCESS;
}

int create_start_file(char *uid, char *name, char *fname, char *start_value, char *timeactive) {
    char start_name[40];
    char start_datetime[DATE_LEN + TIME_LEN + 2];
    FILE *fp;

    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    sprintf(start_datetime, "%04d-%02d-%02d %02d:%02d:%02d",
        timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
        timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

    sprintf(start_name, "AUCTIONS/%03d/START_%03d.txt", next_aid, next_aid);
    if ((fp = fopen(start_name, "w")) == NULL) {
        return ERROR;
    }
    fprintf(fp, "%s %s %s %s %s %s %ld", uid, name, fname, start_value,
        timeactive, start_datetime, rawtime);
    fclose(fp);
    return SUCCESS;
}

// TODO: create_asset_file

int add_user_auction(char *uid) {
    char user_auction_name[40];
    FILE *fp;
    
    sprintf(user_auction_name, "USERS/%s/HOSTED/%03d.txt", uid, next_aid);
    if ((fp = fopen(user_auction_name, "w")) == NULL) {
        return ERROR;
    }
    fclose(fp);
    return SUCCESS;
}

int create_end_file(char *aid, time_t end_fulltime) {
    char end_filename[40];
    char start_filename[40];
    char end_datetime[DATE_LEN + TIME_LEN + 2];
    long start_fulltime;
    FILE *fp;

    sprintf(start_filename, "AUCTIONS/%s/START_%s.txt", aid, aid);
    if ((fp = fopen(start_filename, "r")) == NULL) {
        return ERROR;
    }
    fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %ld", &start_fulltime);
    fclose(fp);

    struct tm *timeinfo;
    timeinfo = localtime(&end_fulltime);

    sprintf(end_datetime, "%04d-%02d-%02d %02d:%02d:%02d",
        timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
        timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

    sprintf(end_filename, "AUCTIONS/%s/END_%s.txt", aid, aid);
    if ((fp = fopen(end_filename, "w")) == NULL) {
        return ERROR;
    }
    fprintf(fp, "%s %ld", end_datetime, end_fulltime - start_fulltime);
    fclose(fp);
    return SUCCESS;
}

int find_auction(char *aid) {
    DIR *d = opendir("AUCTIONS");
    struct dirent *p;

    while ((p = readdir(d))) {
        if (!strncmp(p->d_name, aid, 3)) {
            closedir(d);
            return SUCCESS;
        }
    }

    closedir(d);
    return NON_EXIST;
}

int find_end(char *aid) {
    char end_name[50];
    FILE *fp;

    sprintf(end_name, "AUCTIONS/%s/END_%s.txt", aid, aid);
    if ((fp = fopen(end_name, "r")) == NULL) {
        if (errno == ENOENT) {
            return NON_EXIST;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int check_auction_state(char *aid) {
    if (find_end(aid) == SUCCESS) {
        return CLOSED;
    }

    char start_filename[40];
    long start_fulltime, timeactive;
    FILE *fp;

    sprintf(start_filename, "AUCTIONS/%s/START_%s.txt", aid, aid);
    if ((fp = fopen(start_filename, "r")) == NULL) {
        return ERROR;
    }
    fscanf(fp, "%*s %*s %*s %*s %ld %*s %*s %ld", &timeactive, &start_fulltime);
    fclose(fp);

    time_t curr_fulltime;
    time(&curr_fulltime);

    if ((curr_fulltime - start_fulltime) > timeactive) {
        create_end_file(aid, start_fulltime + timeactive);
        return CLOSED;
    } else {
        return OPEN;
    }
}

long get_max_bid_value(char *aid) {
    char dirname[50];
    sprintf(dirname, "AUCTIONS/%s/BIDS", aid);

    DIR *d = opendir(dirname);
    struct dirent *p = readdir(d);
    char bid_value_str[AUCTION_VALUE_LEN];
    long max_bid_value = 0, bid_value, start_value = 0;
    int count = 0;

    while ((p = readdir(d))) {
        if (!strcmp(p->d_name, "..") || !strcmp(p->d_name, ".")) {
            continue;
        }
        memcpy(bid_value_str, p->d_name, AUCTION_VALUE_LEN);
        bid_value = atol(bid_value_str);
        if (bid_value > max_bid_value) {
            max_bid_value = bid_value;
        }
        count++;
    }

    if (!count) {
        char start_filename[40];
        FILE *fp;
        sprintf(start_filename, "AUCTIONS/%s/START_%s.txt", aid, aid);
        if ((fp = fopen(start_filename, "r")) == NULL) {
            return ERROR;
        }
        fscanf(fp, "%*s %*s %*s %ld %*s %*s %*s %*s", &start_value);
        fclose(fp);
    }

    closedir(d);
    return (start_value > max_bid_value) ? start_value : max_bid_value;
}

int add_bid(char *uid, char *aid, long value) {
    char bid_filename[50];
    char start_filename[50];
    long start_fulltime;
    char bid_datetime[DATE_LEN + TIME_LEN + 2];
    FILE *fp;

    sprintf(start_filename, "AUCTIONS/%s/START_%s.txt", aid, aid);
    if ((fp = fopen(start_filename, "r")) == NULL) {
        return ERROR;
    }
    fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %ld", &start_fulltime);
    fclose(fp);

    time_t bid_fulltime;
    time(&bid_fulltime);
    struct tm *timeinfo;
    timeinfo = localtime(&bid_fulltime);

    sprintf(bid_datetime, "%04d-%02d-%02d %02d:%02d:%02d",
        timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
        timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

    sprintf(bid_filename, "AUCTIONS/%s/BIDS/%06ld.txt", aid, value);
    if ((fp = fopen(bid_filename, "w")) == NULL) {
        return ERROR;
    }

    fprintf(fp, "%s %ld %s %ld", uid, value, bid_datetime, bid_fulltime - start_fulltime);
    fclose(fp);
    return SUCCESS;
}

int add_bidded(char *uid, char *aid) {
    char bidded_filename[50];
    FILE *fp;

    sprintf(bidded_filename, "USERS/%s/BIDDED/%s.txt", uid, aid);
    if ((fp = fopen(bidded_filename, "w")) == NULL) {
        return ERROR;
    }
    fclose(fp);
    return SUCCESS;
}

// TODO: função mais geral para encontrar ficheiro numa diretoria

int find_user_auction(char *uid, char *aid) {
    char dirname[50];
    sprintf(dirname, "USERS/%s/HOSTED", uid);

    DIR *d = opendir(dirname);
    struct dirent *p;

    while ((p = readdir(d))) {
        if (!strncmp(p->d_name, aid, 3)) {
            closedir(d);
            return SUCCESS;
        }
    }

    closedir(d);
    return NON_EXIST;
}

int extract_user_auctions(char *uid, char *buffer) {
    char dirname[50];
    sprintf(dirname, "USERS/%s/HOSTED", uid);

    DIR *d = opendir(dirname);
    struct dirent *p = readdir(d);
    char aid[AUCTION_ID_LEN];
    int count = 0, state;
    ssize_t printed = 0;

    while ((p = readdir(d))) {
        if (!strcmp(p->d_name, "..") || !strcmp(p->d_name, ".")) {
            continue;
        }
        memcpy(aid, p->d_name, AUCTION_ID_LEN);
        state = (check_auction_state(aid) == CLOSED) ? 0 : 1;
        printed = sprintf(buffer+printed, " %s %d", aid, state);
        count++;
    }

    closedir(d);
    return count;
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
        if (sendto(fd, "RLI REG\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        int ret2 = find_password(uid);
        if (ret2 == NON_EXIST) {
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
    if (ret == NON_EXIST) {
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
            } else if (ret2 == NON_EXIST) {
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
    if (ret == NON_EXIST) {
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
            } else if (ret2 == NON_EXIST) {
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
    if (ret == NON_EXIST) {
        if (write(fd, "ROA NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == ERROR) {
        printf("ERROR\n");
    } else if (ret == SUCCESS) {
        create_auction_dir();
        create_start_file(uid, name, fname, start_value, timeactive);
        add_user_auction(uid);
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
    } else if (ret == NON_EXIST) {
        if (write(fd, "RCL NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS && ret2 == NON_EXIST) {
        if (write(fd, "RCL EAU\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS && ret2 == SUCCESS && ret3 == NON_EXIST) {
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
    } else if (ret == NON_EXIST) {
        if (sendto(fd, "RMA NLG\n", 8, 0, server_addr, server_addrlen) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret == SUCCESS) {
        char auctions[BUFSIZ_L];
        int count = extract_user_auctions(uid, auctions);
        if (!count) {
            if (sendto(fd, "RMA NOK\n", 8, 0, server_addr, server_addrlen) == -1) {
                printf("ERROR\n");
                return;
            }
        } else {
            char buffer[BUFSIZ_L+7];
            memset(buffer, 0, BUFSIZ_L+7);
            sprintf(buffer, "RMA OK%s\n", auctions);
            printf("buffer: %s\n", buffer);
            if (sendto(fd, buffer, strlen(buffer), 0, server_addr, server_addrlen) == -1) {
                printf("ERROR4\n");
                return;
            }
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
    } else if (ret == NON_EXIST) {
        if (write(fd, "RBD NLG\n", 8) == -1) {
            printf("ERROR\n");
            return;
        }
    } else if (ret2 == NON_EXIST) {
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
    } else if (!strcmp(label, "LST")) {
        udp_send(fd, "RST OK\n");
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
        udp_send(fd, "RMB OK\n");
    } else if (!strcmp(label, "LST")) {
        udp_send(fd, "RST OK\n");
    } else if (!strcmp(label, "SRC")) {
        udp_send(fd, "RRC OK\n");
    } else {
        printf("Received unreconizable message: %s\n", buffer);
    }
}

void client_listener() {
    int new_fd, max_fd;

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

        int max_fd = fd_udp > fd_tcp ? fd_udp : fd_tcp;

        if (select(max_fd + 1, &rfds, NULL, NULL, NULL) == -1) {
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(fd_tcp, &rfds)) {
            if ((new_fd = accept(fd_tcp, server_addr, &server_addrlen)) == -1) {
                exit(EXIT_FAILURE);
            }
            tcp_command_choser(new_fd);
        }

        if (FD_ISSET(fd_udp, &rfds)) {
            udp_command_choser(fd_udp);
        }
    }

    close(max_fd);
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

    client_listener();
}