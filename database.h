#ifndef _AS_DBFUNC_H_
#define _AS_DBFUNC_H_

#include <time.h>

#include "auction.h"

#define BUFSIZ_S 256
#define BUFSIZ_M 2048
#define BUFSIZ_L 6144

#define SUCCESS 0
#define ERROR -1
#define NOT_FOUND -2

#define USER_NOT_LOGGED_IN -2
#define USER_NOT_REGISTERED -3
#define WRONG_PASSWORD -4
#define REACHED_AUCTION_MAX -5

#define CLOSED 3
#define OPEN 4

typedef struct {
	char uid[USER_ID_LEN+1];
	char name[AUCTION_NAME_MAX_LEN+1];
	char fname[FILE_NAME_MAX_LEN+1];
	char value[AUCTION_VALUE_MAX_LEN+1];
	char date[DATE_LEN+1];
	char time[TIME_LEN+1];
	char timeactive[AUCTION_DURATION_MAX_LEN+1];
} start_info_t;

typedef struct {
    char uid[USER_ID_LEN+1];
    char value[AUCTION_VALUE_MAX_LEN+1];
	char date[DATE_LEN+1];
	char time[TIME_LEN+1];
	char sec_time[AUCTION_DURATION_MAX_LEN+1];
} bid_info_t;

typedef struct {
	char date[DATE_LEN+1];
	char time[TIME_LEN+1];
	char sec_time[AUCTION_DURATION_MAX_LEN+1];
} end_info_t;

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

int get_asset_file_info(char *aid, char *fname, off_t *fsize);

int send_asset_file(int fd, char *aid, char *fname, off_t fsize);

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

int extract_auction_start_info(char *aid, start_info_t *start_info);

int extract_auctions_bids_info(char *aid, bid_info_t *bids);

int extract_auction_end_info(char *aid, end_info_t *end_info);

int create_auction(char *password, start_info_t *auction);

#endif