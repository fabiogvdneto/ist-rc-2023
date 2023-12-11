all: user.c auction.c server.c
	gcc -Wall -Wextra user.c auction.c -o user
	gcc -Wall -Wextra server.c auction.c -o server

server: server.c auction.c
	gcc -Wall -Wextra server.c auction.c -o server

user: user.c auction.c
	gcc -Wall -Wextra user.c auction.c -o user

clean:
	rm -f user server
	rm -f -r output/
	rm -f -r USERS AUCTIONS
	mkdir USERS
	mkdir AUCTIONS
