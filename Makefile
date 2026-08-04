# Makefile for compiling the BPF XDP-Spectre Program

CLANG ?= clang
LLC ?= llc
CC ?= gcc

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
ARCH ?= $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64/arm64/)

SRC_DIR = backend/app/ebpf
OBJ_DIR = backend/app/ebpf

all: $(OBJ_DIR)/xdp_drop.o

$(OBJ_DIR)/xdp_drop.o: $(SRC_DIR)/xdp_drop.c
	$(CLANG) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(ARCH) \
		-I $(KERNEL_SRC)/include \
		-I $(KERNEL_SRC)/arch/$(ARCH)/include \
		-I $(KERNEL_SRC)/include/uapi \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o $(OBJ_DIR)/xdp_drop.ll $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(OBJ_DIR)/xdp_drop.ll

clean:
	rm -f $(OBJ_DIR)/xdp_drop.ll $(OBJ_DIR)/xdp_drop.o

.PHONY: all clean
