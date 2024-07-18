CC = gcc
OBJ = dint
SOURCES = dint.c

OPENSSL_LIBS = -L./openssl-3.0.13 -lcrypto -lssl -ldl -lpthread -static

$(OBJ): $(SOURCES)
	$(CC) -o $@ $^ $(OPENSSL_LIBS)

clean:
	rm -f $(OBJ)
