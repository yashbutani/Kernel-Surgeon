# surgeon.mk - LLVM IR build helper for KernelSurgeon
#
# Usage:
#   make -f surgeon.mk KERNEL_DIR=~/linux TARGET_DIR=net/netfilter/
#   make -f surgeon.mk KERNEL_DIR=~/linux                          # full kernel
#
# Produces .ll/.i files alongside .o files via `-save-temps=obj`, which
# KernelSurgeon's `--mode llvm` consumes. Requires clang + LLVM toolchain.

KERNEL_DIR ?= $(HOME)/linux
TARGET_DIR ?= net/netfilter/
CORES      ?= $(shell nproc)

.PHONY: all config build verify

all: config build verify

config:
	@echo "\n[+] Step 1: Generating default kernel configuration..."
	make -C $(KERNEL_DIR) defconfig

build:
	@echo "\n[+] Step 2: Executing LLVM surgical build on $(TARGET_DIR)..."
	make -C $(KERNEL_DIR) CC=clang LLVM=1 KCFLAGS='-save-temps=obj' -j$(CORES) $(TARGET_DIR)

verify:
	@echo "\n[+] Step 3: Verifying preprocessed file extraction..."
	@echo "Found the following number of .i files ready for Layer 0 ingestion:"
	@find $(KERNEL_DIR)/$(TARGET_DIR) -type f -name "*.i" | wc -l