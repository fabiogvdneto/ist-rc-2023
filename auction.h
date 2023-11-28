#ifndef _AUCTION_H_
#define _AUCTION_H_

#define USER_ID_LEN 6
#define USER_PWD_LEN 8
#define AUCTION_ID_LEN 3
#define AUCTION_NAME_LEN 10
#define ASSET_NAME_LEN 24
#define ASSET_NAME_EXTENSION_LEN 3
#define AUCTION_DURATION_LEN 5
#define AUCTION_VALUE_LEN 6
#define FILENAME_LEN 24

/*
#define UDP_REQUEST_LOGIN "LIN"
#define UDP_REQUEST_LOGOUT "LOU"
#define UDP_REQUEST_UNREGISTER "UNR"
#define UDP_REQUEST_MYAUCTIONS "LMA"
#define UDP_REQUEST_MYBIDS "LMB"
#define UDP_REQUEST_LIST "LST"
#define UDP_REQUEST_SHOW_RECORD "SRC"

#define UDP_REPLY_LOGIN "RLI"
#define UDP_REPLY_LOGOUT "RLO"
#define UDP_REPLY_UNREGISTER "RUR"
#define UDP_REPLY_MYAUCTIONS "RMA"
#define UDP_REPLY_MYBIDS "RMB"
#define UDP_REPLY_LIST "RLS"
#define UDP_REPLY_SHOW_RECORD "RRC"

#define TCP_REQUEST_OPEN "OPA"
#define TCP_REQUEST_CLOSE "CLS"
#define TCP_REQUEST_SHOW_ASSET "SAS"
#define TCP_REQUEST_BID "BID"

#define TCP_REPLY_OPEN "ROA"
#define TCP_REPLY_CLOSE "RCL"
#define TCP_REPLY_SHOW_ASSET "RSA"
#define TCP_REPLY_BID "RBD"

#define STATUS_OK "OK"
#define STATUS_NOT_OK "NOK"
#define STATUS_ILEGAL "ILG"
#define STATUS_NOT_LOGGED_IN "NGL"
*/

int validate_user_id(char *str);

int validate_user_password(char *str);

int validate_auction_name(char *str);

int validate_asset_name(char *str);

int validate_auction_duration(char *str);

int validate_auction_value(char *str);

int validate_auction_id(char *str);

#endif