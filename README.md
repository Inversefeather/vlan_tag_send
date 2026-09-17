# VLAN Tag Switch Test Tool (Windows)

基于 WinPcap/Npcap 的 VLAN tag 报文测试工具，**模拟交换机行为**，报文到 3 层 (IP+UDP)，**VLAN tag 可选**。支持 **iperf 带宽测试**。

## 文件结构

```
.
├── vlan_tag_switch.c   # 主程序（-s 服务端, -c 客户端, -t iperf测试）
├── Makefile            # 编译脚本
└── README.md           # 说明文档
```

---

## 工作原理

```
┌──────────┐   VLAN+IP+UDP frame   ┌──────────┐   VLAN+IP+UDP frame   ┌──────────┐
│  Client  │ ──────────────────── > │ Firewall │ ──────────────────── > │  Server  │
│          │   MAC+[VLAN]+IP+UDP+data│          │                        │          │
│          │ <────────────────────  │          │ <────────────────────  │          │
└──────────┘   Reply with VLAN tag  └──────────┘   Reply with VLAN tag  └──────────┘
```

**核心行为**：
1. **发送时**：payload → UDP头 → IP头 → [VLAN tag] → 以太网头 → 发送
2. **接收时**：收到帧 → 剥以太网头 → [剥VLAN tag] → 剥IP/UDP头 → 提取 payload 打印
3. **自动 ARP 解析**：只需知道对端 IP，自动获取 MAC 地址
4. **VLAN 可选**：不指定 `-v` 时不带 VLAN tag，指定 `-v <vlan_id>` 时带 VLAN tag

---

## 环境要求

1. **WinPcap 或 Npcap** 运行时库
   - 下载地址: https://npcap.com/#download
   - 安装时勾选 "Install Npcap in WinPcap API-compatible Mode"

2. **WinPcap/Npcap SDK**（编译时需要）
   - WinPcap SDK: https://www.winpcap.org/devel.htm (WpdPack)

3. **编译器**：MinGW-w64 或 Visual Studio

---

## 编译

```bash
# MinGW (需要确保 mingw64\bin 在 PATH 中优先于 Git for Windows 的 mingw64\bin)
set PATH=C:\msys64\mingw64\bin;%PATH%
mingw32-make

# 或手动编译
gcc -Wall -O2 -IC:\npcap-sdk-1.16\Include -o vlan_tag_switch.exe vlan_tag_switch.c ^
    -LC:\npcap-sdk-1.16\Lib\x64 -lwpcap -lPacket -lws2_32 -liphlpapi
```

> **注意**：如果安装了 Git for Windows，确保 MSYS2 的 `mingw64\bin` 在 PATH 中排在 Git 的 `mingw64\bin` 之前，否则会因 DLL 版本冲突导致编译失败（无错误输出，直接退出）。

---

## 使用方法

### 1. 列出可用网卡

```bash
vlan_tag_switch.exe -l
```

### 2. 服务端模式

```bash
vlan_tag_switch.exe -s [-p <port>] [-a <ip>] [-v <vlan_id>]
```

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-s` | 服务端模式 | - |
| `-p <port>` | 监听端口 | 9999 |
| `-a <ip>` | 监听 IP | 自动获取 |
| `-v <vlan_id>` | VLAN ID（可选，不指定则不带 VLAN） | 无 VLAN |

### 3. 客户端交互模式

```bash
vlan_tag_switch.exe -c <server_ip:port> [-v <vlan_id>] [-i]
```

### 4. iperf 带宽测试模式

**服务端**：
```bash
vlan_tag_switch.exe -s -p 9999 [-v <vlan_id>]
```

**客户端**：
```bash
vlan_tag_switch.exe -c 192.168.1.100:9999 -t [-b <bw>] [-d <sec>] [-l <len>] [-v <vlan_id>]
```

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-t` | iperf 测试模式 | - |
| `-b <bandwidth>` | 目标带宽 (100M, 1G) | 无限制 |
| `-d <duration>` | 测试持续时间（秒） | 10 |
| `-l <length>` | 报文 payload 大小 | 1400 |
| `-v <vlan_id>` | VLAN ID（可选） | 无 VLAN |

---

## 使用示例

### 场景 1：不带 VLAN 的交互测试

**服务端**（机器 B）：
```bash
vlan_tag_switch.exe -s -p 9999
```

**客户端**（机器 A）：
```bash
vlan_tag_switch.exe -c 192.168.1.100:9999
```

### 场景 2：带 VLAN 的交互测试

**服务端**（机器 B）：
```bash
vlan_tag_switch.exe -s -p 9999 -v 100
```

**客户端**（机器 A）：
```bash
vlan_tag_switch.exe -c 192.168.1.100:9999 -v 100
```

### 场景 3：iperf 带宽测试（带 VLAN）

**服务端**（机器 B）：
```bash
vlan_tag_switch.exe -s -p 9999 -v 100
```

**客户端** - 测试 100Mbps：
```bash
vlan_tag_switch.exe -c 192.168.1.100:9999 -t -b 100M -d 30 -v 100
```

**客户端** - 测试 1Gbps：
```bash
vlan_tag_switch.exe -c 192.168.1.100:9999 -t -b 1G -d 30 -l 1400 -v 100
```

### 场景 4：iperf 带宽测试（不带 VLAN）

**服务端**（机器 B）：
```bash
vlan_tag_switch.exe -s -p 9999
```

**客户端** - 无限制打满：
```bash
vlan_tag_switch.exe -c 192.168.1.100:9999 -t -d 30
```

### iperf 输出示例

**客户端输出**（带 VLAN 100）：
```
--- iperf 客户端测试 ---
  目标: 192.168.1.100:9999
  VLAN: 100
  包大小: 1400 bytes (payload)
  目标带宽: 100.00 Mbps
  持续时间: 30 秒
========================================

  [  1.0s] 11.92 MB  100.00 Mbps  ~8517 packets
  [  2.0s] 11.92 MB  100.00 Mbps  ~8517 packets
  ...
  [ 30.0s] 11.92 MB  100.00 Mbps  ~8517 packets

========================================
  [测试完成]
  总时间: 30.00 秒
  总数据: 357.50 MB
  总包数: 255510
  平均带宽: 100.00 Mbps
========================================
```

**服务端输出**（不带 VLAN）：
```
--- iperf 服务端接收 ---
  监听端口: 9999
  VLAN: 无
========================================

  [首个报文] 来自 192.168.1.101:52341
  [  1.0s] 11.92 MB  100.00 Mbps  ~8517 pkts  lost=0 (0.0%)
  [  2.0s] 11.92 MB  100.00 Mbps  ~8517 pkts  lost=0 (0.0%)
  ...
  [ 30.0s] 11.92 MB  100.00 Mbps  ~8517 pkts  lost=3 (0.001%)

========================================
  [接收完成]
  总时间: 30.00 秒
  总数据: 357.50 MB
  总包数: 255510
  丢包数: 3 (0.001%)
  平均带宽: 100.00 Mbps
========================================
```

---

## 报文格式

**带 VLAN 时**：
```
+-------------------+-------------------+
|  目的 MAC (6B)    |   源 MAC (6B)     |
+-------------------+-------------------+
|  TPID 0x8100 (2B) |  TCI (2B)         |  ← VLAN Tag (4B, 可选)
+-------------------+-------------------+
|  IP Header (20B)  |  UDP Header (8B)  |  ← 3 层
+-------------------+-------------------+
|   Payload         |                   |
+-------------------+-------------------+
```

**不带 VLAN 时**：
```
+-------------------+-------------------+
|  目的 MAC (6B)    |   源 MAC (6B)     |
+-------------------+-------------------+
|  EtherType 0x0800 |  IP Header (20B)  |  ← 3 层
+-------------------+-------------------+
|  UDP Header (8B)  |   Payload         |
+-------------------+-------------------+
```

- **TPID**: 0x8100 (802.1Q Tag Protocol Identifier)
- **TCI**: PCP (3bit) + DEI (1bit) + VID (12bit)
- **IP 协议**: UDP (17)
- **VLAN 可选**: 不指定 `-v` 时不带 VLAN tag，指定 `-v <vlan_id>` 时带 VLAN tag

---

## 常见问题

### 找不到适配器
运行 `vlan_tag_switch.exe -l` 查看可用适配器列表。

### ARP 解析失败
- 检查客户端和服务端是否在同一子网
- 检查防火墙是否允许 ARP 报文

### 无回复/超时
- 检查防火墙是否允许带 VLAN tag 的报文通过

### Win7 兼容性
- Npcap **1.7x** 是最后支持 Win7 的版本
- WinPcap 4.1.2 完全支持 Win7
