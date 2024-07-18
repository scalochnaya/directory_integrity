CC = gcc
OBJ = dint
SOURCES = dint.c
PARAMS = -lcrypto -lssl

all: $(OBJ)

$(OBJ): $(SOURCES)
	$(CC) -o $@ $^ $(PARAMS)

clear:
	rm -f $(OBJ)
