CC = gcc
OBJ = dint
SOURCES = dint.c

OPENSSL_LIBS = -lcrypto -ldl -static-libgcc

$(OBJ): $(SOURCES)
	$(CC) -o $@ $^ $(OPENSSL_LIBS)

clean:
	rm -f $(OBJ)
