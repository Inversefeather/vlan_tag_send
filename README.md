# VLAN Tag Switch Test Tool (Windows)

基于 WinPcap/Npcap 的**用户态 TCP/IP 协议栈**测试工具，支持 **TCP/UDP 双栈**、**原生 VLAN tag**、**iperf 等效打流**。所有报文通过原始以太网帧发送，**不依赖操作系统 TCP 栈**。

## 文件结构

```
.
├── src/
│   ├── net.h / net.c          # 核心数据结构、校验和、帧构建/解析
│   ├── tcp_fsm.h / tcp_fsm.c  # TCP 状态机 (RFC 793/1122)、Reno 拥塞控制
│   ├── platform.h / platform.c # pcap 收发、ARP、定时器、网卡管理
│   ├── report.h / report.c    # iperf 格式 + JSON 输出
│   └── main.c                 # CLI + 事件驱动主循环
├── Makefile
└── README.md
```

---

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                      main.c                              │
│  CLI → 事件循环 (timer_walk / send_pending / recv_dispatch) │
├─────────────────────────────────────────────────────────┤
│                    tcp_fsm.c                             │
│  TCP 状态机: CLOSED→SYN_SENT→ESTABLISHED→FIN_WAIT→TIME_WAIT │
│  Reno: 慢启动 / 拥塞避免 / 快速重传 / 快速恢复              │
│  RTT/RTO: RFC 6298    Checksum: RFC 1071 (伪首部)         │
├─────────────────────────────────────────────────────────┤
│                 platform.c / net.c                       │
│  发送: Eth → [VLAN] → IPv4 → TCP/UDP → pcap_sendpacket   │
│  接收: pcap_next_ex → 解析 → 分发到 FSM                   │
│  TCB 查找: 5-tuple + VLAN ID (严格隔离)                    │
└─────────────────────────────────────────────────────────┘
```

**设计原则**：
1. **所有 TCP 报文 = 手构建帧通过 pcap 发送** — 无 OS TCP 栈 (无 bind/connect/socket)
2. **所有 TCP 接收 = pcap 捕获 + 手解析** — 通过 pcap_next_ex/dispatch
3. **VLAN tag 是一等公民** — 可选 (vlan_id=0 表示无 tag)
4. **事件驱动状态机** — 非阻塞单线程循环，无 sleep(1)
5. **5-tuple + VLAN TCB 查找** — VLAN 始终参与 key 匹配
6. **软件校验和** (IP + TCP/UDP 伪首部)
7. **pcap_open_live timeout = 100ms** — 避免 Npcap BSOD
8. **所有发送缓冲区静态/全局/malloc** — 不在栈上

---

## 环境要求

1. **Npcap 运行时库** (推荐)
   - 下载地址: https://npcap.com/#download
   - 安装时勾选 "Install Npcap in WinPcap API-compatible Mode"

2. **Npcap SDK** (编译时需要)
   - 下载: https://npcap.com/#download (SDK 包)
   - 默认路径: `C:\WpdPack`

3. **编译器**: MinGW-w64 (clang 或 gcc)

---

## 编译

```bash
# 使用 Makefile (自动检测 WpdPack 路径)
make

# 或手动编译
clang -Wall -Wextra -O2 -std=c11 -DUSE_WINPCAP -Ic:/WpdPack/Include -Isrc ^
    -o vlan_tag_switch.exe src/main.c src/net.c src/tcp_fsm.c src/platform.c src/report.c ^
    -lws2_32 -liphlpapi -lwinmm -lshlwapi -Lc:/WpdPack/Lib/x64 -lwpcap -lPacket
```

---

## 使用方法

### 通用参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-s` | 服务端模式 | - |
| `-c <host>` | 客户端模式，指定服务端 IP | - |
| `-p <port>` | 端口 | 9999 |
| `-u` | UDP 模式 (默认 TCP) | TCP |
| `-b #[KMG]` | 目标带宽 (如 100M, 1G) | 无限制 |
| `-t <sec>` | 测试持续时间 (秒) | 10 |
| `-n #[KMG]` | 发送字节数 (优先于 -t) | 0 |
| `-l <len>` | 发送缓冲区大小 | 1460 |
| `-i <sec>` | 报告间隔 (秒) | 1 |
| `-P <N>` | 并行流数量 | 1 |
| `-V <id>` | VLAN ID (1-4094, 默认无 VLAN) | 无 |
| `--pcp <n>` | VLAN PCP 优先级 (0-7) | 0 |
| `-B <addr>` | 绑定网卡 (IP 或名称子串, 默认首张网卡) | 0.0.0.0 |
| `-T <sec>` | 服务端静默超时 (秒) | 3 |
| `-J` | JSON 格式输出 | - |
| `-v` | 详细输出 | - |
| `-h` | 帮助 | - |

### 示例

#### TCP 带宽测试 (单流)

**服务端**:
```bash
vlan_tag_switch.exe -s -p 9999
```

**客户端** (100Mbps, 30秒):
```bash
vlan_tag_switch.exe -c 192.168.1.100 -b 100M -t 30
```

#### TCP 带宽测试 (4 并行流, 带 VLAN)

**服务端**:
```bash
vlan_tag_switch.exe -s -p 9999 -V 100
```

**客户端**:
```bash
vlan_tag_switch.exe -c 192.168.1.100 -b 1G -t 30 -P 4 -V 100
```

#### UDP 带宽测试

**服务端**:
```bash
vlan_tag_switch.exe -s -p 9999 -u
```

**客户端** (1Gbps):
```bash
vlan_tag_switch.exe -c 192.168.1.100 -u -b 1G -t 30
```

#### 指定网卡

**按 IP 绑定**:
```bash
vlan_tag_switch.exe -s -p 9999 -B 192.168.1.50
```

**按名称绑定** (模糊匹配):
```bash
vlan_tag_switch.exe -s -p 9999 -B "Ethernet"
```

#### JSON 输出

```bash
vlan_tag_switch.exe -c 192.168.1.100 -b 1G -t 10 -J
```

输出示例:
```json
{
  "streams": [
    {"id": 1, "bytes": 1192092876, "seconds": 10.0, "mbps": 953.67, "retransmits": 0}
  ]
}
```

---

## 输出示例

### 客户端 (TCP, 100Mbps)

```
Bind: 192.168.1.50  MAC=AA:BB:CC:DD:EE:FF  VLAN=100
Available adapters:
  [0] Intel(R) Ethernet  192.168.1.50  AA:BB:CC:DD:EE:FF
  [1] Realtek PCIe GbE   10.0.0.5       11:22:33:44:55:66
Sniffing on \Device\NPF_{...}
TCP client: 1 stream(s) -> 192.168.1.100:9999 VLAN=100 buf=1460
[ ID] Interval       Transfer     Bandwidth
[  1] 0.00-1.00 sec  11.92 MBytes  100.00 Mbits/sec
[  2] 1.00-2.00 sec  11.92 MBytes  100.00 Mbits/sec
...
[ 30] 29.00-30.00 sec  11.92 MBytes  100.00 Mbits/sec
- - - - - - - - - - - - - - - - - - - - - - - - -
[  30]  0.00-30.00 sec  357.5 MBytes  100.00 Mbits/sec
```

### 服务端 (TCP, 接收)

```
Bind: 192.168.1.50  MAC=AA:BB:CC:DD:EE:FF  VLAN=100
Available adapters:
  [0] Intel(R) Ethernet  192.168.1.50  AA:BB:CC:DD:EE:FF
Sniffing on \Device\NPF_{...}
TCP server: port=9999 VLAN=100 bind=0.0.0.0 (listening...)
[ ID] Interval       Transfer     Bandwidth
[  1] 0.00-1.00 sec  11.92 MBytes  100.00 Mbits/sec
[  2] 1.00-2.00 sec  11.92 MBytes  100.00 Mbits/sec
...
- - - - - - - - - - - - - - - - - - - - - - - - -
[  30]  0.00-30.00 sec  357.5 MBytes  100.00 Mbits/sec
```

---

## 报文格式

**带 VLAN 时** (最大 1522 字节):
```
 DMAC(6) | SMAC(6) | TPID 0x8100(2) | TCI(2) | EtherType(2) | IP(20) | TCP(20) | Payload(≤1460) | FCS(4)
```

**不带 VLAN 时** (最大 1518 字节):
```
 DMAC(6) | SMAC(6) | EtherType 0x88B5(2) | IP(20) | TCP(20) | Payload(≤1460) | FCS(4)
```

- **MSS**: 1460 (无 VLAN) / 1456 (带 VLAN)
- **TPID**: 0x8100 (802.1Q)
- **TCI**: PCP(3bit) + DEI(1bit) + VID(12bit)
- **EtherType**: `0x88B5` (IEEE 802 实验类型), **不是** `0x0800` (IPv4)。
  原因: 若用 0x0800, 对端机器的 OS 协议栈会看到 SYN 并回 RST (无 socket 监听该端口),
  本软件的对端永远抢不过 OS。0x88B5 是 OS 不认识的类型, 完全忽略, 只有 Npcap 捕获层能看到。
  Wireshark 默认不解析该类型为 IPv4, 如需查看可手动解码或配置 Wireshark 的 "Decode As"。

---

## 技术规格

| 特性 | 实现 |
|---|---|
| TCP 状态机 | RFC 793 + RFC 1122 |
| 拥塞控制 | Reno (慢启动 / 拥塞避免 / 快速重传 / 快速恢复) |
| RTO 计算 | RFC 6298 (SRTT = 7/8·SRTT + 1/8·RRT, RTTVAR = 3/4·RTTVAR + 1/4·\|Δ\|) |
| RTO 退避 | RFC 2988 §5.5 (RTO = min(RTO·2, RTO_MAX)) |
| 快速重传 | RFC 5681 (3 dup ACK, 仅在 recover 期间触发) |
| 快速恢复退出 | RFC 5681 §3.2 (RTO 必须无条件退出 Fast Recovery) |
| 校验和 | RFC 1071 (IP + TCP/UDP 伪首部) |
| 序列号比较 | SEQ_LT/LEQ/GT/GEQ 宏 (处理 32 位回绕) |
| TCB 查找 | 5-tuple + VLAN ID (严格隔离, 无条件编译) |
| 并行流 | 每流独立 TCB / 拥塞控制 / pacing |
| Pacing | 事件驱动 + 速率限制 (busy-spin 安全) |
| EtherType | 0x88B5 (避开 OS 协议栈, 避免 RST 抢占) |
| 输出格式 | iperf 兼容 + JSON |

---

## 常见问题

### 找不到适配器
启动时会自动列出所有可用适配器。使用 `-B` 按 IP 或名称绑定。

### ARP 解析失败
- 检查客户端和服务端是否在同一子网
- 检查防火墙是否允许 ARP 报文

### 无回复/超时
- 检查防火墙是否允许带 VLAN tag 的报文通过
- 确认两端 VLAN ID 一致

### 多网卡环境
- 使用 `-B <ip>` 或 `-B <name>` 明确绑定网卡
- 启动时输出的适配器列表可帮助确认选择

### Win7 兼容性
- Npcap **1.7x** 是最后支持 Win7 的版本
- snaplen 已设为 2048 (避免 65536 兼容问题)

---

## 注意事项

- **必须以管理员身份运行** (pcap 需要)
- **对端必须是本工具的另一个实例** (不支持标准 iperf 服务器)
- TCP 模式下所有报文走原始以太网帧，**操作系统看不到这些连接**
- Ctrl+C 通过 InterlockedExchange + pcap_breakloop 优雅退出
