all:
	gcc -Wall spoofer.c dns_helpers.c -o spoofer -lpthread -lnet