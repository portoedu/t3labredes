all:
	gcc server.c checksum.c -o server
	gcc cliente.c checksum.c -o client -lm
clean:
	rm -f client server ex.txt
