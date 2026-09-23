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
WINDIVERT = /c/WinDivert-2.2.2

CC = clang

CFLAGS = -Wall -Wextra -O2 -std=c11 -DUSE_WINPCAP
CFLAGS += -I$(WPDPACK)/Include
CFLAGS += -I$(WINDIVERT)/Include
CFLAGS += -Isrc
CFLAGS += -DWINDIVERT_STATIC

LIBS = -lws2_32 -liphlpapi -lwinmm -lshlwapi
LIBS += -L$(WPDPACK)/Lib/x64 -lwpcap -lPacket

SRCS = src/main.c src/net.c src/tcp_fsm.c src/platform.c src/report.c src/rst_killer.c
SRCS += src/windivert_static.c src/iperf.c
TARGET = vlan_tag_switch.exe

# WinDivert source is third-party; it has a known UNICODE/wchar mismatch in
# its driver-install path (never reached when the driver is pre-installed)
# and uses offsetof without including <stddef.h>.  Compile it with those
# specific warnings disabled and stddef.h force-included.
WINDIVERT_CFLAGS = -Wno-incompatible-pointer-types -Wno-missing-field-initializers
WINDIVERT_CFLAGS += -Wno-unused-parameter -Wno-unused-value
WINDIVERT_CFLAGS += -include stddef.h

OBJS = $(SRCS:.c=.o)

all: $(TARGET)
	@echo "Built: $(TARGET)"

$(TARGET): $(OBJS) src/net.h src/tcp_fsm.h src/platform.h src/report.h src/rst_killer.h src/windivert_static.h src/main.h src/iperf.h
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

# Default rule for our own sources
src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Special rule for the third-party WinDivert static blob
src/windivert_static.o: src/windivert_static.c src/windivert_static.h
	$(CC) $(CFLAGS) $(WINDIVERT_CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
