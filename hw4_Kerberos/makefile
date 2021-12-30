CC=mpicc
INC_DIR=include
SRC_DIR=src
BIN_DIR=bin
CFLAGS= -std=c99 -g
TARGET=kerberos

SOURCE_FILES=$(shell find $(SRC_DIR) -name '*.c')

$(BIN_DIR)/${TARGET}: $(SOURCE_FILES)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -Iinclude $^ -o $@ -lm

.PHONY: clean
clean:
	rm -r bin