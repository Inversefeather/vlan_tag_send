#
# Makefile for iperf-like bandwidth test tool (Windows)
#
# Compilers:
#   mingw32-make CC=clang    # Use clang (recommended)
#   mingw32-make CC=gcc       # Use gcc (if available)
#
# Targets:
#   mingw32-make              # Socket mode only (TCP/UDP, no WinPcap needed)
#   mingw32-make raw          # Raw Ethernet + VLAN mode (requires WinPcap)
#   mingw32-make clean        # Clean build
#
# WinPcap SDK path (adjust if installed elsewhere)
WPDPACK = /c/WpdPack

CC ?= clang

# Compiler flags
CFLAGS = -Wall -Wextra -O2 -std=c11

# Link libraries (Winsock + IP helper + multimedia timer)
LIBS = -lws2_32 -liphlpapi -lwinmm

TARGET = vlan_tag_switch.exe

# Socket mode (default) - no external dependencies
all: $(TARGET)
	@echo "Built: $(TARGET) (compiler: $(CC))"

$(TARGET): vlan_tag_switch.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Raw mode - requires WinPcap/WpdPack
raw: CFLAGS += -DUSE_WINPCAP -I$(WPDPACK)/Include
raw: LIBS += -L$(WPDPACK)/Lib/x64 -lwpcap -lPacket
raw: $(TARGET)_raw
	@echo "Built: $(TARGET)_raw (raw mode with WinPCAP)"

$(TARGET)_raw: vlan_tag_switch.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET) $(TARGET)_raw

.PHONY: all raw clean
