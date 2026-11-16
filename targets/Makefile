# Build the benchmark targets at two optimisation levels (and with clang if
# present) to exercise LeakScope "across compilers and optimization levels".

CC      ?= gcc
COMMON  := -fno-stack-protector -fno-builtin -fcf-protection=none -g -no-pie
BIN     := bin
SRC     := src/targets.c

BINARIES := $(BIN)/targets_gcc_O2 $(BIN)/targets_gcc_O0
CLANG := $(shell command -v clang 2>/dev/null)
ifneq ($(CLANG),)
BINARIES += $(BIN)/targets_clang_O2
endif

all: $(BINARIES)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/targets_gcc_O2: $(SRC) | $(BIN)
	gcc -O2 $(COMMON) $< -o $@

$(BIN)/targets_gcc_O0: $(SRC) | $(BIN)
	gcc -O0 $(COMMON) $< -o $@

$(BIN)/targets_clang_O2: $(SRC) | $(BIN)
	clang -O2 $(COMMON) $< -o $@

clean:
	rm -rf $(BIN)

.PHONY: all clean
