user: user.c auction.c
	gcc -Wall -Wextra user.c auction.c -o user

server: server.c
	gcc -Wall -Wextra server.c auction.c -o server

clean:
	rm -f user server
	rm -f -r output/
	rm -f -r USERS AUCTIONS
	mkdir USERS
	mkdir AUCTIONS
