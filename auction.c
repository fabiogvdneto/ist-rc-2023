#include <ctype.h>

#include "auction.h"

int validate_user_id(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < USER_ID_LEN) {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}

int validate_user_password(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < USER_PWD_LEN) {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}

int validate_auction_name(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < AUCTION_NAME_LEN) {
        if (!isalnum(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}

int validate_asset_name(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < ASSET_NAME_LEN-ASSET_NAME_EXTENSION_LEN) {
        if (!(isalnum(str[i]) || (str[i] == '-') || (str[i] == '_') || (str[i++] == '.'))) {
            return 0;
        }
    }
    while (i < ASSET_NAME_LEN) {
        if (!isalpha(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}

int validate_auction_duration(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < AUCTION_DURATION_LEN) {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}

int validate_auction_value(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < AUCTION_VALUE_LEN) {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}

int validate_auction_id(char *str) {
    if (!str) return 0;

    int i = 0;
    while (i < AID_LEN) {
        if (!isdigit(str[i++])) {
            return 0;
        }
    }
    return (str[i] == '\0');
}