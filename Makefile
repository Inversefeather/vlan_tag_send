#
# Makefile for VLAN tag switch test tool (Windows - WinPcap/Npcap)
#
# 需要安装 WinPcap 或 Npcap SDK
# SDK 默认路径: C:\WpdPack 或 C:\Npcap SDK
#
# 用法:
#   MinGW:  mingw32-make
#   MSVC:   nmake -f Makefile CC=cl
#

# WinPcap/Npcap SDK 路径 (根据实际情况修改)
WPDPACK_DIR ?= C:\npcap-sdk-1.16

# 编译器选择: gcc 或 cl (MSVC)
CC ?= gcc

ifeq ($(CC),gcc)
    CFLAGS  = -Wall -Wextra -O2 -std=c11 -I$(WPDPACK_DIR)\Include
    LDFLAGS = -L$(WPDPACK_DIR)\Lib\x64
    LIBS    = -lwpcap -lPacket -lws2_32 -liphlpapi
    RM      = rm -f
    EXE     =
else
    # MSVC
    CFLAGS  = /W3 /O2 /I$(WPDPACK_DIR)\Include
    LDFLAGS = /LIBPATH:$(WPDPACK_DIR)\Lib
    LIBS    = wpcap.lib Packet.lib ws2_32.lib iphlpapi.lib
    RM      = del /F
    EXE     = .exe
endif

all: vlan_tag_switch$(EXE)

vlan_tag_switch$(EXE): vlan_tag_switch.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean:
	$(RM) vlan_tag_switch$(EXE)

.PHONY: all clean
