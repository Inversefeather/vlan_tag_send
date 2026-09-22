#
# Makefile - Raw TCP/UDP bandwidth test tool with VLAN tag support
#
# All traffic = raw Ethernet frames via pcap. No OS TCP stack.
#
# Targets:
#   make              -> build (requires WinPcap/Npcap SDK)
#   make clean        -> clean
#
# WinPcap/Npcap SDK path (adjust to your install)
WPDPACK = /c/WpdPack

CC ?= clang

CFLAGS = -Wall -Wextra -O2 -std=c11 -DUSE_WINPCAP
CFLAGS += -I$(WPDPACK)/Include
CFLAGS += -Isrc

LIBS = -lws2_32 -liphlpapi -lwinmm -lshlwapi
LIBS += -L$(WPDPACK)/Lib/x64 -lwpcap -lPacket

SRCS = src/main.c src/net.c src/tcp_fsm.c src/platform.c src/report.c
TARGET = vlan_tag_switch.exe

all: $(TARGET)
	@echo "Built: $(TARGET)"

$(TARGET): $(SRCS) src/net.h src/tcp_fsm.h src/platform.h src/report.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
