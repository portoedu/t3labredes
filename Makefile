all:
	gcc server.c checksum.c -o server
	gcc cliente.c checksum.c -o client
clean:
	rm -f client server ex.txt
