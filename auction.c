#include <ctype.h>

#include "auction.h"

int validate_user_id(char *str) {
    if (!str) return 0;

    for (int i = 0; i < USER_ID_LEN; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    return (*str == '\0');
}

int validate_user_password(char *str) {
    if (!str) return 0;

    for (int i = 0; i < USER_PWD_LEN; i++) {
        if (!isalnum(*str++)) {
            return 0;
        }
    }

    return (*str == '\0');
}

int validate_auction_name(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_NAME_LEN; i++, str++) {
        if (!isalnum(*str)) {
            return (*str == '\0');
        }
    }

    return 0;
}

int validate_asset_name(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= ASSET_NAME_LEN; i++, str++) {
        char c = *str;

        // Check if all characters  are either alphanumeric or '-', '_', '.'.
        if (!(isalnum(c) || (c == '-') || (c == '_') || (c == '.'))) {
            if ((c != '\0') || (i < 5)) return 0;

            // Check if last 3 characters are letters.
            for (i = 0; i < ASSET_NAME_EXTENSION_LEN; i++) {
                if (!isalpha(*(--str))) {
                    return 0;
                }
            }

            // Check if there is a dot between name and extension.
            return (*(--str) == '.');
        }
    }
    
    return 0;
}

int validate_auction_duration(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_DURATION_LEN; i++, str++) {
        if (!isdigit(*str)) {
            return (*str == '\0');
        }
    }
    
    return 0;
}

int validate_auction_value(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_VALUE_LEN; i++, str++) {
        if (!isdigit(*str)) {
            return (*str == '\0');
        }
    }
    
    return 0;
}

int validate_auction_id(char *str) {
    if (!str) return 0;

    for (int i = 0; i < AUCTION_ID_LEN; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    return (*str == '\0');
}