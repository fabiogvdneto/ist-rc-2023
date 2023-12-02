#ifndef _AUCTION_H_
#define _AUCTION_H_

#define USER_ID_LEN 6
#define USER_PWD_LEN 8
#define AUCTION_ID_MAX_LEN 3
#define AUCTION_NAME_MAX_LEN 10
#define FILE_NAME_MAX_LEN 24
#define FILE_NAME_EXTENSION_LEN 3
#define FILE_SIZE_MAX_LEN 10
#define AUCTION_DURATION_MAX_LEN 5
#define AUCTION_VALUE_LEN 6
#define FILENAME_LEN 24

int validate_user_id(char *str);

int validate_user_password(char *str);

int validate_auction_name(char *str);

int validate_file_name(char *str);

int validate_file_size(char *str);

int validate_auction_duration(char *str);

int validate_auction_value(char *str);

int validate_auction_id(char *str);

#endif