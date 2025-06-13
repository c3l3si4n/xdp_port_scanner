# You may need to install clang, llc, and libbpf-dev (or similar package
# that provides linux/bpf.h and bpf/bpf_helpers.h).
# On Debian/Ubuntu: sudo apt-get install clang llvm libbpf-dev
# On Fedora/CentOS: sudo dnf install clang llvm libbpf-devel

CLANG ?= clang
TARGET_ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS = -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(TARGET_ARCH)

# This path may need to be adjusted depending on your system
BPF_INCLUDE_PATH ?= /usr/include/bpf

all: xdp_filter.o

xdp_filter.o: xdp_filter.c
	$(CLANG) $(CFLAGS) -I$(BPF_INCLUDE_PATH) -c $< -o $@

clean:
	rm -f xdp_filter.o 