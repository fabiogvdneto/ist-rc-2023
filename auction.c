#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "auction.h"

int days_of_month[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

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

int validate_file_name(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= FILE_NAME_MAX_LEN; i++, str++) {
        char c = *str;

        // Check if all characters  are either alphanumeric or '-', '_', '.'.
        if (!(isalnum(c) || (c == '-') || (c == '_') || (c == '.'))) {
            if ((c != '\0') || (i < 5)) return 0;

            // Check if last 3 characters are letters.
            for (i = 0; i < FILE_NAME_EXTENSION_LEN; i++) {
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

int validate_file_size(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= FILE_SIZE_MAX_LEN; i++, str++) {
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

int validate_auction_name(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_NAME_MAX_LEN; i++, str++) {
        if (!(isalnum(*str) || (*str == '-') || (*str == '_') || (*str == '.'))) {
            return (*str == '\0');
        }
    }

    return 0;
}

int validate_auction_duration(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_DURATION_MAX_LEN; i++, str++) {
        if (!isdigit(*str)) {
            return (*str == '\0');
        }
    }
    
    return 0;
}

int validate_auction_value(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_VALUE_MAX_LEN; i++, str++) {
        if (!isdigit(*str)) {
            return (*str == '\0');
        }
    }
    
    return 0;
}

int validate_auction_state(char *str) {
    return str && (strlen(str) == 1) && ((*str == '0') || (*str == '1'));
}

// Format: YYYY-MM-DD
int validate_date(char *str) {
    if (!str) return 0;

    int y = atoi(str);
    for (int i = 0; i < 4; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    if ((*str++ != '-') || (y < 0) || (y >= 3000)) return 0;

    int m = atoi(str);
    for (int i = 0; i < 2; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    if ((*str++ != '-') || (m < 1) || (m > 12)) return 0;

    int d = atoi(str);
    for (int i = 0; i < 2; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    return (*str == '\0') && (d >= 1) && (d <= days_of_month[m-1]);
}

// Format: HH:MM:SS
int validate_time(char *str) {
    if (!str) return 0;

    int h = atoi(str);
    for (int i = 0; i < 2; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    if ((*str++ != ':') || (h < 0) || (h >= 24)) return 0;

    int m = atoi(str);
    for (int i = 0; i < 2; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    if ((*str++ != ':') || (m < 0) || (m >= 60)) return 0;

    int s = atoi(str);
    for (int i = 0; i < 2; i++) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    return (*str == '\0') && (s >= 0) && (s < 60);
}

int validate_elapsed_time(char *str) {
    if (!str) return 0;

    while (*str) {
        if (!isdigit(*str++)) {
            return 0;
        }
    }

    return 1;
}

/*
 *  Returns true if the given memory region follows the syntax rules of the auction protocol.
 *  A well-structured protocol message is composed by arguments, separated by exactly one space,
 * and ends with an end-line character.
 *  It is only recommended to use this function on protocol messages that do not include binary data
 * (e.g. files) and that fit in a single buffer.
 */
int validate_protocol_message(char *str, int length) {
    if (str[--length] != '\n') return 0;

    while (--length >= 0) {
        if ((str[length] == '\0') || (str[length] == '\n')) {
            return 0;
        }

        if ((str[length] == ' ') && (str[length+1] == ' ')) {
            return 0;
        }
    }

    return 1;
}