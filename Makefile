CFLAGS = -Wall -Wextra

all: user server

user: user.c auction.c utils.c

server: server.c auction.c utils.c

clean:
	rm -f user server

purge:
	rm -rf USERS AUCTIONS
	rm -rf output
