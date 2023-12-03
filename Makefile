user: user.c auction.c
	gcc -Wall -Wextra user.c auction.c -o user

AS: AS.c
	gcc -Wall -Wextra AS.c -o AS

clean:
	rm -f user AS
	rm -f -r output/
