SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

ifeq ($(PREFIX),)
	PREFIX := $(HOME)/.local
endif

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OUT = $(BIN_DIR)/bot

CC      = gcc
CFLAGS  = -D_GNU_SOURCE -D_DEFAULT_SOURCE -Iinclude -Wall -Wextra -g
LDLIBS  = -lssl -lcrypto -lconfig++ -lpthread -lpcre2-8 -lsqlite3

all: $(OUT)

$(OUT): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

.PHONY: clean install

clean:
	$(RM) -rv $(OBJ_DIR) $(OUT)

install: $(OUT)
	install -d $(PREFIX)/bin/
	install -m 0755 $(OUT) $(PREFIX)/bin/
