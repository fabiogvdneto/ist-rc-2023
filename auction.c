#include <ctype.h>

#include "auction.h"

int validate_user_id(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i == USER_UID_LEN);
}

int validate_user_password(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }

    return (i == USER_PWD_LEN);
}

int validate_auction_name(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }

    return (i <= AUCTION_NAME_LEN);
}

int validate_asset_name(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!(isalnum(str[i]) || str[i] == '-' 
            || str[i] == '_' || str[i] == '.')) {
                return 0;
            }
        i++;
    }

    return (i <= ASSET_NAME_LEN);
}

int validate_auction_duration(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i <= AUCTION_DURATION_LEN);
}

int validate_auction_value(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i <= AUCTION_VALUE_LEN);
}

int validate_auction_id(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }

    return (i == AID_LEN);
}