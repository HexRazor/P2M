# Minimal Makefile to build sudoadd BPF program and user binary
# Usage: make -f Makefile.sudoadd

CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool

BPF_SRC := sudoadd.bpf.c
BPF_OBJ := .output/sudoadd.bpf.o
BPF_TMP := .output/sudoadd.tmp.bpf.o
SKEL := .output/sudoadd.skel.h

USR_SRC := sudoadd.c
USR_OBJ := .output/sudoadd.o
USR_BIN := sudoadd

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf

PKG_CONFIG := $(shell command -v pkg-config >/dev/null 2>&1 && echo yes)
ifeq ($(PKG_CONFIG),yes)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)
else
LIBBPF_CFLAGS := -I/usr/include
LIBBPF_LIBS := -lbpf -lelf -lz
endif

.PHONY: all clean build-bpf gen-skel build-user

all: build-bpf gen-skel build-user

build-bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) | .output
	@echo "[BPF] compiling $(BPF_SRC) -> $(BPF_TMP)"
	$(CLANG) $(BPF_CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $(BPF_TMP)
	@echo "[BPF] generating object $(BPF_OBJ)"
	$(BPFTOOL) gen object $(BPF_OBJ) $(BPF_TMP)

gen-skel: $(SKEL)

$(SKEL): $(BPF_OBJ)
	@echo "[BPF] generating skeleton $(SKEL)"
	$(BPFTOOL) gen skeleton $< > $@

build-user: $(USR_BIN)

$(USR_BIN): $(USR_OBJ)
	@echo "[USR] linking $@"
	$(CC) $(CFLAGS) $^ $(LIBBPF_LIBS) -o $@

$(USR_OBJ): $(USR_SRC) $(SKEL) | .output
	@echo "[USR] compiling $(USR_SRC)"
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I.output -c $< -o $@

.output:
	mkdir -p .output

clean:
	@echo "Cleaning artifacts"
	rm -rf .output $(USR_BIN)

