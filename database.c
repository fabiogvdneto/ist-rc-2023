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

/* Files */
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include "database.h"

#include "auction.h"
#include "utils.h"

int create_user_dir(char *uid) {
    char uid_dirname[60];
    char hosted_dirname[60];
    char bidded_dirname[60];

    sprintf(uid_dirname, "USERS/%s", uid);
    if ((mkdir(uid_dirname, S_IRWXU)) == -1) {
        return ERROR;
    }

    sprintf(hosted_dirname, "USERS/%s/HOSTED", uid);
    if ((mkdir(hosted_dirname, S_IRWXU)) == -1) {
        rmdir(uid_dirname);
        return ERROR;
    }

    sprintf(bidded_dirname, "USERS/%s/BIDDED", uid);
    if ((mkdir(bidded_dirname, S_IRWXU)) == -1) {
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

int create_login(char *uid) {
    char login_name[60];
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
    char login_name[60];

    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    unlink(login_name);
    return SUCCESS;
}

int find_login(char *uid) {
    if (find_user_dir(uid) == NOT_FOUND) {
        return NOT_FOUND;
    }

    char login_name[60];
    FILE *fp;

    sprintf(login_name, "USERS/%s/%s_login.txt", uid, uid);
    if ((fp = fopen(login_name, "r")) == NULL) {
        if (errno == ENOENT) {
            return NOT_FOUND;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int create_password(char *uid, char *pwd) {
    char pass_name[60];
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
    char pass_name[60];
    FILE *fp;

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(pass_name, "r")) == NULL) {
        return ERROR;
    }

    if (fread(ext_pwd, sizeof(char), USER_PWD_LEN, fp) != USER_PWD_LEN) {
        return ERROR;
    }
    fclose(fp);

    ext_pwd[USER_PWD_LEN] = '\0';

    return SUCCESS;
}

int erase_password(char *uid) {
    char pass_name[60];

    sprintf(pass_name, "USERS/%s/%s_pass.txt", uid, uid);
    unlink(pass_name);
    return SUCCESS;
}

int find_password(char *uid) {
    if (find_user_dir(uid) == NOT_FOUND) {
        return NOT_FOUND;
    }

    char password_name[60];
    FILE *fp;

    sprintf(password_name, "USERS/%s/%s_pass.txt", uid, uid);
    if ((fp = fopen(password_name, "r")) == NULL) {
        if (errno == ENOENT) {
            return NOT_FOUND;
        } else {
            return ERROR;
        }
    }
    fclose(fp);
    return SUCCESS;
}

int create_auction_dir(int next_aid) {
    char aid_dirname[60];
    char asset_dirname[60];
    char bids_dirname[60];

    sprintf(aid_dirname, "AUCTIONS/%03d", next_aid);
    if ((mkdir(aid_dirname, S_IRWXU)) == -1) {
        return ERROR;
    }

    sprintf(asset_dirname, "AUCTIONS/%03d/ASSET", next_aid);
    if ((mkdir(asset_dirname, S_IRWXU)) == -1) {
        rmdir(aid_dirname);
        return ERROR;
    }

    sprintf(bids_dirname, "AUCTIONS/%03d/BIDS", next_aid);
    if ((mkdir(bids_dirname, S_IRWXU)) == -1) {
        rmdir(aid_dirname);
        rmdir(asset_dirname);
        return ERROR;
    }

    return SUCCESS;
}

int create_start_file(int next_aid, char *uid, char *name, char *fname, char *start_value, char *timeactive) {
    char start_name[60];
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

int create_asset_file(int next_aid, int fd, char *fname, off_t fsize, char *first_bytes, ssize_t to_write) {
    char asset_filename[60];
    sprintf(asset_filename, "AUCTIONS/%03d/ASSET/%s", next_aid, fname);

    int asset_fd = open(asset_filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU);
    if (fd == -1) {
        return ERROR;
    }

    ssize_t written = write_all_bytes(asset_fd, first_bytes, to_write);
    fsize -= written;
    char buffer[BUFSIZ_L];
    ssize_t readd, to_read = (fsize < BUFSIZ_L) ? fsize : BUFSIZ_L;
    while (fsize) {
        readd = read_all_bytes(fd, buffer, to_read);
        written = write_all_bytes(asset_fd, buffer, readd);
        fsize -= written;
        to_read = (fsize < BUFSIZ_L) ? fsize : BUFSIZ_L;
    }

    close(asset_fd);
    return SUCCESS;
}

int get_asset_file_info(char *aid, char *fname, off_t *fsize) {
    char asset_dirname[60];
    sprintf(asset_dirname, "AUCTIONS/%s/ASSET", aid);

    DIR *d = opendir(asset_dirname);
    struct dirent *p;
    while ((p = readdir(d))) {
        if (!validate_file_name(p->d_name)) {
            continue;
        }
        printf("%s\n", p->d_name);
        strcpy(fname, p->d_name);
        break;
    }
    closedir(d);

    char asset_filename[60];
    sprintf(asset_filename, "AUCTIONS/%s/ASSET/%s", aid, fname);
    int asset_fd = open(asset_filename, O_RDONLY);
    if (asset_fd == -1) {
        return ERROR;
    }

    struct stat statbuf;
    if (fstat(asset_fd, &statbuf) == -1) {
        close(asset_fd);
        return ERROR;
    }
    printf("%ld\n", statbuf.st_size);
    *fsize = statbuf.st_size;

    close(asset_fd);
    return SUCCESS;
}

int send_asset_file(int fd, char* aid, char* fname, off_t fsize) {
    char asset_filename[60];
    sprintf(asset_filename, "AUCTIONS/%s/ASSET/%s", aid, fname);
    int asset_fd = open(asset_filename, O_RDONLY);
    if (asset_fd == -1) {
        return ERROR;
    }

    if ((sendfile(fd, asset_fd, NULL, fsize)) == -1) {
        return ERROR;
    }

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

    if ((curr_fulltime - start_fulltime) > timeactive) {
        create_end_file(aid, start_fulltime + timeactive);
        return CLOSED;
    } else {
        return OPEN;
    }
}

long get_max_bid_value(char *aid) {
    char dirname[60];
    sprintf(dirname, "AUCTIONS/%s/BIDS", aid);

    DIR *d = opendir(dirname);
    struct dirent *p = readdir(d);
    char bid_value_str[AUCTION_VALUE_MAX_LEN];
    long max_bid_value = 0, bid_value, start_value = 0;
    int count = 0;

    while ((p = readdir(d))) {
        if (!strcmp(p->d_name, "..") || !strcmp(p->d_name, ".")) {
            continue;
        }
        memcpy(bid_value_str, p->d_name, AUCTION_VALUE_MAX_LEN);
        bid_value = atol(bid_value_str);
        if (bid_value > max_bid_value) {
            max_bid_value = bid_value;
        }
        count++;
    }

    if (!count) {
        char start_filename[60];
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

int update_next_aid() {
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

// TODO: função mais geral para encontrar ficheiro numa diretoria

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