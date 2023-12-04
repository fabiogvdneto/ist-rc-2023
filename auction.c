#include <ctype.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

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

int validate_auction_id(char *str) {
    if (!str) return 0;

    for (int i = 0; i < AUCTION_ID_LEN; i++) {
        if (!isdigit(*str++)) {
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

int validate_auction_name(char *str) {
    if (!str) return 0;

    for (int i = 0; i <= AUCTION_NAME_MAX_LEN; i++, str++) {
        if (!isalnum(*str)) {
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

    for (int i = 0; i <= AUCTION_VALUE_LEN; i++, str++) {
        if (!isdigit(*str)) {
            return (*str == '\0');
        }
    }
    
    return 0;
}

int validate_date(char *str) {
    if (!str) return 0;

    if (strlen(str) != DATE_LEN) return 0;

    if (str[4] != '-' || str[7] != '-') return 0;

    char date[DATE_LEN];
    memcpy(date, str, DATE_LEN);

    char *delim = "-\n";

    char *year = strtok(date, delim);
    for (int i = 0; i < 4; i++) {
        if (!isdigit(year[i])) {
            return 0;
        }
    }
    int year_num = atoi(year);
    if (atoi(year) <= 0) return 0;

    char *month = strtok(NULL, delim);
    if (!isdigit(month[0]) || !isdigit(month[1])) return 0;
    int month_num = atoi(month);
    if (month_num < 1 || month_num > 12) return 0;

    char *day = strtok(NULL, delim);
    if (!isdigit(day[0]) || !isdigit(day[1])) return 0;
    int day_num = atoi(day);
    int month_days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month_num == 2 && day_num == 29 &&
        !(year_num%400 == 0 || (year_num%4 == 0 && year_num%100 != 0))) {
            return 0;
    } else if (day_num < 1 || day_num > month_days[month_num-1]) {
        return 0;
    }

    return 1;
}

int validate_time(char *str) {
    if (!str) return 0;

    if (strlen(str) != TIME_LEN) return 0;

    if (str[2] != ':' || str[5] != ':') {
        return 0;
    }

    char time[TIME_LEN];
    memcpy(time, str, TIME_LEN);

    char *delim = ":\n";

    char *hour = strtok(time, delim);
    if (!isdigit(hour[0] || !isdigit(hour[1]))) return 0;
    if (atoi(hour) < 0 || atoi(hour) > 23) return 0;

    char *minutes = strtok(NULL, delim);
    if (!isdigit(minutes[0]) || !isdigit(minutes[1])) return 0;
    if (atoi(minutes) < 0 || atoi(minutes) > 59) return 0;

    char *seconds = strtok(NULL, delim);
    if (!isdigit(seconds[0]) || !isdigit(seconds[1])) return 0;
    if (atoi(seconds) < 0 || atoi(seconds) > 59) return 0;

    return 1;
}