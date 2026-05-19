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
	make -C $(KERNEL_DIR) LLVM=1 defconfig
	@echo "[+] Switching kernel config to ThinLTO and disabling WERROR..."
	$(KERNEL_DIR)/scripts/config --file $(KERNEL_DIR)/.config \
		-d LTO_CLANG_FULL \
		-e LTO_CLANG_THIN \
		-d WERROR
	@echo "[+] Finalizing config..."
	make -C $(KERNEL_DIR) LLVM=1 olddefconfig

build:
	@echo "\n[+] Step 2: Executing LLVM surgical build on $(TARGET_DIR)..."
	make -C $(KERNEL_DIR) \
		CC=clang LLVM=1 \
		KCFLAGS='-save-temps=obj -Wno-unused-value' \
		WERROR=0 \
		-j$(CORES) $(TARGET_DIR)

verify:
	@echo "\n[+] Step 3: Verifying preprocessed file extraction..."
	@echo "Found the following number of .i files ready for Layer 0 ingestion:"
	@find $(KERNEL_DIR)/$(TARGET_DIR) -type f -name "*.i" | wc -l

# # surgeon.mk - KernelSurgeon Target Build Automation
# # Location: ~/kernelsurgeon/surgeon.mk
# # Target: ~/v5.10/
# #
# # Usage:
# #   make -f surgeon.mk FILE=net/netfilter/
# #   make -f surgeon.mk FILE=drivers/net/ethernet/ build
# #   make -f surgeon.mk FILE=fs/ext4/ verify

# # ifndef FILE
# # $(error FILE is required. Usage: make -f surgeon.mk FILE=<path/to/target/>)
# # endif

# KERNEL_DIR = $(HOME)/v6.19.9
# TARGET_DIR = $(FILE)
# CORES ?= $(shell nproc)

# .PHONY: all config build verify

# all: config build verify

# config:
# 	@echo "\n[+] Step 1: Generating default kernel configuration..."
# 	make -C $(KERNEL_DIR) defconfig

# build:
# 	@echo "\n[+] Step 2: Executing LLVM surgical build on $(TARGET_DIR)..."
# 	make -C $(KERNEL_DIR) CC=clang LLVM=1 KCFLAGS='-save-temps=obj' -j$(CORES) $(TARGET_DIR)

# verify:
# 	@echo "\n[+] Step 3: Verifying preprocessed file extraction..."
# 	@echo "Found the following number of .i files ready for Layer 0 ingestion:"
# 	@find $(KERNEL_DIR)/$(TARGET_DIR) -type f -name "*.i" | wc -l
