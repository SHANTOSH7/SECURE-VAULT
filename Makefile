CC = gcc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -Iinclude
CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion

ifeq ($(OS),Windows_NT)
    OPENSSL_CFLAGS :=
    OPENSSL_LIBS := -lcrypto -luser32 -lkernel32
    TARGET := securevault.exe
else
    OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl)
    OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl)
    TARGET := securevault
endif

CFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

SOURCES = src/main.c src/ui.c src/auth.c src/crypto.c src/storage.c src/vault.c src/password.c src/platform/platform.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean run check
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

src/%.o: src/%.c include/sv.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

src/platform/%.o: src/platform/%.c include/sv.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

check: $(TARGET)
	@echo "Build completed. Run ./$(TARGET) for the interactive smoke test."

clean:
	rm -f $(OBJECTS) $(TARGET) tests/test_crypto

.PHONY: test
tests/test_crypto: tests/test_crypto.c src/crypto.c src/platform/platform.c include/sv.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_crypto.c src/crypto.c src/platform/platform.c -o $@ $(LDFLAGS)

test: tests/test_crypto
	./tests/test_crypto
