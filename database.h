#ifndef _AS_DBFUNC_H_
#define _AS_DBFUNC_H_

#include <time.h>

#define BUFSIZ_S 256
#define BUFSIZ_M 2048
#define BUFSIZ_L 6144

#define NOT_FOUND 2
#define SUCCESS 1
#define ERROR -1

#define CLOSED 3
#define OPEN 4

int create_user_dir(char *uid);

int erase_dir(char *dirname);

int erase_user_dir(char *uid);

int find_user_dir(char *uid);

int create_login(char *uid);

int erase_login(char *uid);

int find_login(char *uid);

int create_password(char *uid, char *pwd);

int extract_password(char *uid, char *ext_pwd);

int erase_password(char *uid);

int find_password(char *uid);

int create_auction_dir(int next_aid);

int create_start_file(int next_aid, char *uid, char *name, char *fname, 
        char *start_value, char *timeactive);

// TODO: create_asset_file

int add_user_auction(int next_aid, char *uid);

int create_end_file(char *aid, time_t end_fulltime);

int find_auction(char *aid);

int find_end(char *aid);

int check_auction_state(char *aid);

long get_max_bid_value(char *aid);

int update_next_aid();

int add_bid(char *uid, char *aid, long value);

// TODO: função mais geral para encontrar ficheiro numa diretoria

int add_bidded(char *uid, char *aid);

int find_user_auction(char *uid, char *aid);

int extract_user_auctions(char *uid, char *auctions);

int extract_user_bidded_auctions(char *uid, char* bidded);

int extract_auctions(char* auctions);

// as três últimas talvez se possam juntar numa só

int extract_auction_start_info(char *aid, char *host_uid, char *name, char *fname,
        char *start_value, char *start_date, char *start_time, char *timeactive);

int extract_auctions_bids_info(char *aid, char **bidder_uid, char **bid_value,
        char **bid_date, char **bid_time, char **bid_sec_time);

#endif