user: user.c
	gcc -Wall -Wextra user.c -o user

AS: AS.c
	gcc -Wall -Wextra AS.c -o AS

clean:
	rm -f user AS
