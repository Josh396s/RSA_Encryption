CC = clang
CFLAGS = -Wall -Wextra -Werror -Wpedantic $(shell pkg-config --cflags gmp)
LFLAGS = $(shell pkg-config --libs gmp)

all: keygen encrypt decrypt

keygen: keygen.o randstate.o numtheory.o rsa.o
	$(CC) -o keygen keygen.o randstate.o numtheory.o rsa.o  $(LFLAGS)

encrypt: encrypt.o randstate.o numtheory.o rsa.o
	$(CC) -o encrypt encrypt.o randstate.o numtheory.o rsa.o $(LFLAGS)

decrypt: decrypt.o randstate.o numtheory.o rsa.o
	 $(CC) -o decrypt decrypt.o randstate.o numtheory.o rsa.o $(LFLAGS)

keygen.o: keygen.c
	$(CC) $(CFLAGS) -c keygen.c

encrypt.o: encrypt.c
	$(CC) $(CFLAGS) -c encrypt.c

decrypt.o: decrypt.c
	$(CC) $(CFLAGS) -c decrypt.c

randstate.o: randstate.c
	$(CC) $(CFLAGS) -c randstate.c

numtheory.o: numtheory.c
	$(CC) $(CFLAGS) -c numtheory.c

rsa.o: rsa.c
	$(CC) $(CFLAGS) -c rsa.c

clean:
	rm -f rsa *.o randstate *.o numtheory *.o decrypt *.o encrypt *.o keygen *.o

format:
	clang-format -i -style=file *.[ch]
