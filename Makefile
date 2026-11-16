# LeakScope (C implementation).
#
#   make              build build/leakscope, build/leakscope-bench and the benchmark targets
#   make test         build and run the test suite
#   make bench        run the benchmark against ground truth (gcc -O2)
#   make bench-all    ... across every compiler build
#   make install      install the `leakscope` command (PREFIX=/usr/local)
#
# Dependencies: Capstone (>= 4) and Unicorn (>= 2) development files, found via
# pkg-config.  Debian/Ubuntu: apt install libcapstone-dev libunicorn-dev
# To build against libraries elsewhere, override DEP_CFLAGS / DEP_LIBS, e.g.
#   make DEP_CFLAGS="-I/opt/cs/include -I/opt/uc/include" \
#        DEP_LIBS="-L/opt/cs/lib -lcapstone -L/opt/uc/lib -lunicorn"

CC       ?= cc
CFLAGS   ?= -O2 -g
WARN     := -std=c11 -Wall -Wextra -Wshadow -D_GNU_SOURCE -Isrc
LDFLAGS  ?=
PKGS     := capstone unicorn
DEP_CFLAGS ?= $(shell pkg-config --cflags $(PKGS) 2>/dev/null)
DEP_LIBS   ?= $(shell pkg-config --libs $(PKGS) 2>/dev/null || echo -lcapstone -lunicorn)
PREFIX   ?= /usr/local
BUILD    ?= build

LIB_SRC  := src/util.c src/json.c src/elfload.c src/target.c src/trace.c \
            src/taint.c src/machine.c src/analyze.c src/report.c src/cli.c
LIB_OBJ  := $(LIB_SRC:src/%.c=$(BUILD)/%.o)
HEADERS  := $(wildcard src/*.h)

.PHONY: all tool targets test bench bench-all install clean

all: tool targets

tool: $(BUILD)/leakscope $(BUILD)/leakscope-bench

targets:            ## build the benchmark binaries
	$(MAKE) -C targets

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $(DEP_CFLAGS) -c $< -o $@

$(BUILD)/libleakscope.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/leakscope: src/main.c $(BUILD)/libleakscope.a
	$(CC) $(WARN) $(CFLAGS) $(DEP_CFLAGS) $< $(BUILD)/libleakscope.a $(LDFLAGS) $(DEP_LIBS) -o $@

$(BUILD)/leakscope-bench: tools/bench.c $(BUILD)/libleakscope.a $(HEADERS)
	$(CC) $(WARN) $(CFLAGS) $(DEP_CFLAGS) $< $(BUILD)/libleakscope.a $(LDFLAGS) $(DEP_LIBS) -o $@

$(BUILD)/test_leakscope: tests/test_leakscope.c $(BUILD)/libleakscope.a $(HEADERS)
	$(CC) $(WARN) $(CFLAGS) $(DEP_CFLAGS) $< $(BUILD)/libleakscope.a $(LDFLAGS) $(DEP_LIBS) -o $@

test: $(BUILD)/test_leakscope targets
	./$(BUILD)/test_leakscope

bench: $(BUILD)/leakscope-bench targets
	./$(BUILD)/leakscope-bench

bench-all: $(BUILD)/leakscope-bench targets
	./$(BUILD)/leakscope-bench
	./$(BUILD)/leakscope-bench --binary targets/bin/targets_gcc_O0
	-./$(BUILD)/leakscope-bench --binary targets/bin/targets_clang_O2

install: $(BUILD)/leakscope
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BUILD)/leakscope $(DESTDIR)$(PREFIX)/bin/leakscope

clean:
	$(MAKE) -C targets clean
	rm -rf $(BUILD)
