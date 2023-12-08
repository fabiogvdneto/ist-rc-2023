#ifndef _AUCTION_H_
#define _AUCTION_H_

#define USER_ID_LEN 6
#define USER_PWD_LEN 8
#define AUCTION_ID_LEN 3
#define AUCTION_NAME_MAX_LEN 10
#define FILE_NAME_MAX_LEN 24
#define FILE_NAME_EXTENSION_LEN 3
#define FILE_SIZE_MAX_LEN 8
#define AUCTION_DURATION_MAX_LEN 5
#define AUCTION_VALUE_LEN 6
#define FILENAME_LEN 24
#define DATE_LEN 10
#define TIME_LEN 8
#define ELAPSED_TIME_LEN 5

int validate_user_id(char *str);

int validate_user_password(char *str);

int validate_file_name(char *str);

int validate_file_size(char *str);

int validate_auction_id(char *str);

int validate_auction_name(char *str);

int validate_auction_duration(char *str);

int validate_auction_value(char *str);

int validate_auction_state(char *str);

int validate_date(char *str);

int validate_time(char *str);

int validate_elapsed_time(char *str);

int validate_protocol_message(char *str, int length);

#endif