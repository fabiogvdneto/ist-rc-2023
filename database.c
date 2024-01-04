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
#include <sys/sendfile.h>
#include <stdarg.h>

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

// recursively erase a dir
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

int erase_login(char *uid) {
    char login_name[60];

    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    unlink(login_name);
    return SUCCESS;
}

int extract_password(char *uid, char *pwd) {
    char pathname[BUFSIZ_S];
    sprintf(pathname, "USERS/%s/%s_pass.txt", uid, uid);
    FILE *file = fopen(pathname, "r");

    if (file == NULL) {
        if (errno != ENOENT) {
            perror("fopen");
            return ERROR;
        }

        return ERR_USER_NOT_REGISTERED;
    }

    if (fread(pwd, sizeof(char), USER_PWD_LEN, file) != USER_PWD_LEN) {
        perror("fread");
        return ERROR;
    }
    
    fclose(file);

    pwd[USER_PWD_LEN] = '\0';
    return SUCCESS;
}

int erase_password(char *uid) {
    char pass_name[60];

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    unlink(pass_name);
    return SUCCESS;
}

int get_asset_file_info(char *aid, char *fname, off_t *fsize) {
    char buffer[BUFSIZ_S];
    sprintf(buffer, "AUCTIONS/%s/ASSET", aid);

    DIR *d = opendir(buffer);
    struct dirent *p;
    while ((p = readdir(d))) {
        if (!validate_file_name(p->d_name)) {
            continue;
        }
        strcpy(fname, p->d_name);
        break;
    }
    closedir(d);

    sprintf(buffer, "AUCTIONS/%s/ASSET/%s", aid, fname);
    int fd = open(buffer, O_RDONLY);
    if (fd == -1) {
        return ERROR;
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        close(fd);
        return ERROR;
    }

    *fsize = statbuf.st_size;
    close(fd);
    return SUCCESS;
}

int add_user_auction(int next_aid, char *uid) {
    char user_auction_name[60];
    FILE *fp;
    
    sprintf(user_auction_name, "USERS/%s/HOSTED/%03d.txt", uid, next_aid);
    if ((fp = fopen(user_auction_name, "w")) == NULL) {
        return ERROR;
    }
    fclose(fp);
    return SUCCESS;
}

int create_end_file(char *aid, time_t end_fulltime) {
    char end_filename[60];
    char start_filename[60];
    char end_datetime[DATE_LEN + TIME_LEN + 2];
    long start_fulltime;
    FILE *fp;

    // read start info
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
    // write end info
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
    return NOT_FOUND;
}

int find_end(char *aid) {
    char end_name[60];
    FILE *fp;

    sprintf(end_name, "AUCTIONS/%s/END_%s.txt", aid, aid);
    if ((fp = fopen(end_name, "r")) == NULL) {
        if (errno == ENOENT) {
            return NOT_FOUND;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int check_auction_state(char *aid) {
    // if end file is found, then auction has ended
    if (find_end(aid) == SUCCESS) {
        return CLOSED;
    }

    char start_filename[60];
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

    // if end file is not found, calculate time elapsed since start
    // to determine if it already ended or not
    if ((curr_fulltime - start_fulltime) > timeactive) {
        create_end_file(aid, start_fulltime + timeactive);
        return CLOSED;
    } else {
        return OPEN;
    }
}

// get the minimum value for new bids
long get_max_bid_value(char *aid) {
    struct dirent **filelist;
    int n_entries, len;
    int has_bids = 0;
    long start_value, max_bid;

    char dirname[60];
    sprintf(dirname, "AUCTIONS/%s/BIDS", aid);
    n_entries = scandir(dirname, &filelist, 0, alphasort);
    if (n_entries <= 0)
        return 0;
    
    // file names are order ascendently,
    // so start from end to get max bid value
    while (n_entries--) {
        len = strlen(filelist[n_entries]->d_name);
        if (len == AUCTION_VALUE_MAX_LEN+4) { // VVVVVV.txt - length 10
            max_bid = atol(filelist[n_entries]->d_name);
            has_bids = 1;
            break;
        }
        free(filelist[n_entries]);
    }
    free(filelist);

    // if no bids have been placed,
    // then bids have to be bigger than start value
    if (has_bids) {
        return max_bid;
    } else {
        char start_filename[60];
        FILE *fp;
        sprintf(start_filename, "AUCTIONS/%s/START_%s.txt", aid, aid);
        if ((fp = fopen(start_filename, "r")) == NULL) {
            return ERROR;
        }
        fscanf(fp, "%*s %*s %*s %ld %*s %*s %*s %*s", &start_value);
        fclose(fp);
        return start_value;
    }
}

// get the max auction ID existent to determine the ID of the next auction
int get_next_aid() {
    struct dirent **filelist;
    int n_entries, len;
    int max_auction_id = 0;

    n_entries = scandir("AUCTIONS/", &filelist, 0, alphasort);
    if (n_entries <= 0)
        return 0;
    
    while (n_entries--) {
        len = strlen(filelist[n_entries]->d_name);
        if (len == AUCTION_ID_LEN) {
            max_auction_id = atol(filelist[n_entries]->d_name);
            break;
        }
        free(filelist[n_entries]);
    }
    free(filelist);

    return max_auction_id + 1;
}

int add_bid(char *uid, char *aid, long value) {
    char bid_filename[60];
    char start_filename[60];
    long start_fulltime;
    char bid_datetime[DATE_LEN + TIME_LEN + 2];
    FILE *fp;

    // read start full time to determine seconds elapsed since the start
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
    char bidded_filename[60];
    FILE *fp;

    sprintf(bidded_filename, "USERS/%s/BIDDED/%s.txt", uid, aid);
    if ((fp = fopen(bidded_filename, "w")) == NULL) {
        return ERROR;
    }
    fclose(fp);
    return SUCCESS;
}

int find_user_auction(char *uid, char *aid) {
    char dirname[60];
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
    return NOT_FOUND;
}

// extract auctions from given user
int extract_user_auctions(char *uid, char* auctions) {
    char dirname[60];
    sprintf(dirname, "USERS/%s/HOSTED/", uid);
    
    struct dirent **filelist;
    int n_entries, len;
    char aid[AUCTION_ID_LEN+1];
    int count = 0, state, iter = 0;
    ssize_t total_printed = 0, printed = 0;

    n_entries = scandir(dirname, &filelist, 0, alphasort);
    if (n_entries <= 0)
        return ERROR;
    
    while (iter < n_entries) {
        char entry_name[256];
        memcpy(entry_name, filelist[iter]->d_name, 256);
        len = strlen(entry_name);
        if (len == AUCTION_ID_LEN + 4) { // AID.txt
            memcpy(aid, entry_name, AUCTION_ID_LEN);
            aid[AUCTION_ID_LEN] = '\0';
            state = (check_auction_state(aid) == CLOSED) ? 0 : 1;
            printed = sprintf(auctions+total_printed, " %s %d", aid, state);
            if (printed < 0) {
                return ERROR;
            } else {
                total_printed += printed;
            }
            count++;
        }
        free(filelist[iter]);
        iter++;
    }
    free(filelist);

    return count;
}

// extract auctions on which given user has placed bids
int extract_user_bidded_auctions(char *uid, char* bidded) {
    char dirname[60];
    sprintf(dirname, "USERS/%s/BIDDED/", uid);
    
    struct dirent **filelist;
    int n_entries, len;
    char aid[AUCTION_ID_LEN+1];
    int count = 0, state, iter = 0;
    ssize_t total_printed = 0, printed = 0;

    n_entries = scandir(dirname, &filelist, 0, alphasort);
    if (n_entries <= 0)
        return ERROR;
    
    while (iter < n_entries) {
        char entry_name[256];
        memcpy(entry_name, filelist[iter]->d_name, 256);
        len = strlen(entry_name);
        if (len == AUCTION_ID_LEN + 4) { // AID.txt
            memcpy(aid, entry_name, AUCTION_ID_LEN);
            aid[AUCTION_ID_LEN] = '\0';
            state = (check_auction_state(aid) == CLOSED) ? 0 : 1;
            printed = sprintf(bidded+total_printed, " %s %d", aid, state);
            if (printed < 0) {
                return ERROR;
            } else {
                total_printed += printed;
            }
            count++;
        }
        free(filelist[iter]);
        iter++;
    }
    free(filelist);

    return count;
}

// extract all existent auctions
int extract_auctions(char* auctions) {
    struct dirent **filelist;
    int n_entries, len, count = 0, state, iter = 0;
    char aid[AUCTION_ID_LEN+1];
    ssize_t total_printed = 0, printed = 0;

    n_entries = scandir("AUCTIONS", &filelist, 0, alphasort);
    if (n_entries <= 0)
        return ERROR;
    
    while (iter < n_entries) {
        len = strlen(filelist[iter]->d_name);
        if (len == AUCTION_ID_LEN) {
            memcpy(aid, filelist[iter]->d_name, AUCTION_ID_LEN);
            aid[AUCTION_ID_LEN] = '\0';
            state = (check_auction_state(aid) == CLOSED) ? 0 : 1;
            printed = sprintf(auctions+total_printed, " %s %d", aid, state);
            if (printed < 0) {
                return ERROR;
            } else {
                total_printed += printed;
            }
            count++;
        }
        free(filelist[iter]);
        iter++;
    }
    free(filelist);

    return count;
}

int extract_auction_start_info(char *aid, start_info_t *start_info) {
    char start_filename[60];
    FILE *fp;

    sprintf(start_filename, "AUCTIONS/%s/START_%s.txt", aid, aid);
    if (!(fp = fopen(start_filename, "r"))) {
        return ERROR;
    }
    fscanf(fp, "%s %s %s %s %s %s %s", start_info->uid, start_info->name, start_info->fname, 
        start_info->value, start_info->timeactive, start_info->date, start_info->time);
    fclose(fp);
    return SUCCESS;
}

// extract information about all bids placed in a given auction
int extract_auctions_bids_info(char *aid, bid_info_t *bids) {
    char dirname[60];
    sprintf(dirname, "AUCTIONS/%s/BIDS/", aid);

    struct dirent **filelist;
    int n_bids = 0, len, iter = 0;
    FILE *fp;

    int n_entries = scandir(dirname, &filelist, 0, alphasort);
    if (n_entries <= 0) {
        return ERROR;
    }

    char *fds = bids[0].time;
    fds++;
    
    char pathname[BUFSIZ_S+60];
    while (iter < n_entries) {
        len = strlen(filelist[iter]->d_name);
        if (len == AUCTION_VALUE_MAX_LEN + 4) { // VVVVVV.txt
            sprintf(pathname, "%s%s", dirname, filelist[iter]->d_name);
            if (!(fp = fopen(pathname, "r"))) {
                return ERROR;
            }
            fscanf(fp, "%s %s %s %s %s", bids[n_bids].uid, bids[n_bids].value,
                bids[n_bids].date, bids[n_bids].time, bids[n_bids].sec_time);
            n_bids++;
            fclose(fp);
        }
        free(filelist[iter]);
        if (n_bids == 50)
            break;
        iter++;
    }
    free(filelist);

    return n_bids;
}

int extract_auction_end_info(char *aid, end_info_t *end_info) {
    char end_filename[60];
    FILE *fp;

    sprintf(end_filename, "AUCTIONS/%s/END_%s.txt", aid, aid);
    if (!(fp = fopen(end_filename, "r"))) {
        return ERROR;
    }
    fscanf(fp, "%s %s %s", end_info->date, end_info->time, end_info->sec_time);
    fclose(fp);
    return SUCCESS;
}

/* ---- Utils ---- */

int file_exists(char *pathname) {
    FILE *file = fopen(pathname, "r");
    
    if (file != NULL) {
        fclose(file);
        return SUCCESS;
    }

    if (errno != ENOENT) {
        perror("fopen");
        return ERROR;
    }

    return NOT_FOUND;
}

/* ---- Users ---- */

int exists_user_password_file(char *uid) {
    char pathname[BUFSIZ];
    sprintf(pathname, "USERS/%s/%s_pass.txt", uid, uid);
    return file_exists(pathname);
}

int exists_user_login_file(char *uid) {
    char pathname[BUFSIZ_S];
    sprintf(pathname, "USERS/%s/%s_login.txt", uid, uid);
    return file_exists(pathname);
}

int create_user_dirs(char *uid) {
    char buffer[BUFSIZ_S];

    sprintf(buffer, "USERS/%s", uid);
    if ((mkdir(buffer, S_IRWXU) == -1) && (errno != EEXIST)) {
        perror("mkdir");
        return ERROR;
    }

    sprintf(buffer, "USERS/%s/HOSTED", uid);
    if ((mkdir(buffer, S_IRWXU) == -1) && (errno != EEXIST)) {
        perror("mkdir");
        return ERROR;
    }

    sprintf(buffer, "USERS/%s/BIDDED", uid);
    if ((mkdir(buffer, S_IRWXU) == -1) && (errno != EEXIST)) {
        perror("mkdir");
        return ERROR;
    }

    return SUCCESS;
}

int create_user_login_file(char *uid) {
    char pathname[60];
    sprintf(pathname, "USERS/%s/%s_login.txt", uid, uid);

    FILE *file = fopen(pathname, "w");
    if (file == NULL) {
        perror("fopen");
        return ERROR;
    }
    
    fclose(file);
    return SUCCESS;
}

int create_user_password_file(char *uid, char *pwd) {
    char pathname[BUFSIZ_S];
    sprintf(pathname, "USERS/%s/%s_pass.txt", uid, uid);

    FILE *file = fopen(pathname, "w");
    if (file == NULL) {
        perror("fopen");
        return ERROR;
    }

    if (fwrite(pwd, sizeof(char), USER_PWD_LEN, file) < USER_PWD_LEN) {
        perror("fwrite");
        return ERROR;
    }
    
    fclose(file);
    return SUCCESS;
}

int erase_user_dir(char *uid) {
    char uid_dirname[60];

    sprintf(uid_dirname, "USERS/%s", uid);
    erase_dir(uid_dirname);

    return SUCCESS;
}

int find_user_dir(char *uid) {
    char uid_dirname[60];
    FILE *fp;

    sprintf(uid_dirname, "USERS/%s", uid);
    if ((fp = fopen(uid_dirname, "r")) == NULL) {
        if (errno == ENOENT) {
            return NOT_FOUND;
        } else {
            return ERROR;
        }
    }

    fclose(fp);
    return SUCCESS;
}

/**
 * Returns:
 * - ERROR if an error occurred.
 * - ERR_USER_ALREADY_LOGGED_IN if user is already logged in.
 * - ERR_WRONG_PASSWORD if user exists but password does not match.
 * - USER_LOGGED_IN if user was successfully logged in.
 * - USER_REGISTERED if user was successfully registered.
*/
int login(char *uid, char *pwd) {
    int status = exists_user_login_file(uid);

    if (status == ERROR) return ERROR;
    if (status == SUCCESS) return ERR_USER_ALREADY_LOGGED_IN;

    char buffer[BUFSIZ_S];
    switch (exists_user_password_file(uid)) {
        case ERROR:
            return ERROR;
        case NOT_FOUND:
            if (create_user_dirs(uid) == ERROR) return ERROR;
            if (create_user_login_file(uid) == ERROR) return ERROR;
            if (create_user_password_file(uid, pwd) == ERROR) return ERROR;

            return USER_REGISTERED;
        case SUCCESS:
            extract_password(uid, buffer);

            if (strcmp(buffer, pwd)) return ERR_WRONG_PASSWORD;
            if (create_user_login_file(uid) == ERROR) return ERROR;

            return USER_LOGGED_IN;
        default:
            return ERROR;
    }
}

/* ---- Auctions ---- */

int create_auction_dirs(int aid) {
    char pathname[BUFSIZ_S];
    sprintf(pathname, "AUCTIONS/%03d", aid);
    if ((mkdir(pathname, S_IRWXU) == -1) && (errno != EEXIST)) {
        perror("mkdir");
        return ERROR;
    }

    sprintf(pathname, "AUCTIONS/%03d/ASSET", aid);
    if ((mkdir(pathname, S_IRWXU) == -1) && (errno != EEXIST)) {
        perror("mkdir");
        return ERROR;
    }

    sprintf(pathname, "AUCTIONS/%03d/BIDS", aid);
    if ((mkdir(pathname, S_IRWXU) == -1) && (errno != EEXIST)) {
        perror("mkdir");
        return ERROR;
    }

    return SUCCESS;
}

int create_auction_start_file(int aid, start_info_t *auction) {
    char buffer[BUFSIZ_S];
    sprintf(buffer, "AUCTIONS/%03d/START_%03d.txt", aid, aid);
    FILE *file = fopen(buffer, "w");
    if (file == NULL) {
        perror("fopen");
        unlink(auction->fname);
        return ERROR;
    }

    time_t rawtime = time(NULL);

    strftime(buffer, BUFSIZ_S, "%Y-%m-%d %H:%M:%S", localtime(&rawtime));
    fprintf(file, "%s %s %s %s %s %s %ld",
        auction->uid, auction->name, auction->fname, auction->value,
        auction->timeactive, buffer, rawtime
    );
    fclose(file);

    return SUCCESS;
}

int create_auction_hosted_file(int aid, char *uid) {
    char pathname[BUFSIZ_S];
    sprintf(pathname, "USERS/%s/HOSTED/%03d.txt", uid, aid);
    FILE *file = fopen(pathname, "w");

    if (file == NULL) {
        perror("fopen");
        return ERROR;
    }

    fclose(file);
    return SUCCESS;
}

/**
 * Returns:
 * - ERROR if a general error occurred.
 * - ERR_WRONG_PASSWORD if user password does not match.
 * - ERR_REACHED_AUCTION_MAX if the number of auctions reached its maximum.
 * - ERR_USER_NOT_LOGGED_IN if user is not logged in.
 * - SUCCESS if auction was successfully created.
*/
int create_auction(char *password, start_info_t *auction) {
    int ret = exists_user_login_file(auction->uid);

    if (ret == ERROR) return ERROR;
    if (ret == NOT_FOUND) {
        unlink(auction->fname);
        return ERR_USER_NOT_LOGGED_IN;
    }

    char buffer[BUFSIZ_S];
    ret = extract_password(auction->uid, buffer);
    
    if (ret != SUCCESS) {
        unlink(auction->fname);
        return ret;
    }

    if (strcmp(password, buffer)) {
        unlink(auction->fname);
        return ERR_WRONG_PASSWORD;
    }

    int next_auction_id = get_next_aid();

    if (next_auction_id == 1000) {
        unlink(auction->fname);
        return ERR_REACHED_AUCTION_MAX;
    }

    if (create_auction_dirs(next_auction_id) == ERROR) {
        unlink(auction->fname);
        return ERROR;
    }

    if (create_auction_start_file(next_auction_id, auction) == ERROR) {
        unlink(auction->fname);
        return ERROR;
    }

    if (create_auction_hosted_file(next_auction_id, auction->uid) == ERROR) {
        unlink(auction->fname);
        return ERROR;
    }

    sprintf(buffer, "AUCTIONS/%03d/ASSET/%s", next_auction_id, auction->fname);
    if (rename(auction->fname, buffer) == -1) {
        perror("rename");
        unlink(auction->fname);
        return ERROR;
    }

    return next_auction_id++;
}