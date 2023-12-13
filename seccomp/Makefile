BUILD = build
OUTPUT = $(BUILD)/bubblenix-seccomp

CC = gcc
PKG_CONFIG = pkg-config

CFLAGS ?= -O2 -pipe
CFLAGS += -Wall -Wextra -pedantic -std=c17
CFLAGS += $(shell $(PKG_CONFIG) --cflags libseccomp)

LIBS := $(shell $(PKG_CONFIG) --libs libseccomp)

SOURCES = $(wildcard *.c)
HEADERS = $(wildcard *.h)
OBJS = $(addprefix $(BUILD)/, $(patsubst %.c,%.o,$(SOURCES)))

.PHONY: all
all: $(OUTPUT)

.PHONY: clean
clean:
	rm -f $(OUTPUT) $(OBJS)

$(BUILD):
	mkdir -p $@
	touch $@/CACHEDIR.TAG

$(BUILD)/%.o: %.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTPUT): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $@
