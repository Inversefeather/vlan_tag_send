#
# Makefile for iperf-like bandwidth test tool (Windows)
#
# Compilers:
#   mingw32-make CC=clang    # Use clang (recommended)
#   mingw32-make CC=gcc       # Use gcc (if available)
#
# Usage:
#   mingw32-make                    # Build with default compiler
#   mingw32-make clean              # Clean build
#

CC ?= clang

# Compiler flags
CFLAGS = -Wall -Wextra -O2 -std=c11

# Link libraries (Winsock + IP helper)
LIBS = -lws2_32 -liphlpapi

TARGET = vlan_tag_switch.exe

all: $(TARGET)
	@echo "Built: $(TARGET) (compiler: $(CC))"

$(TARGET): vlan_tag_switch.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
