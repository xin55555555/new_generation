#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ddos_classifier.py  —  DDoS 攻击抓包全类型分类归档脚本
版本：v5.5  （2026-05-26）

变更说明（v5.5）：
  1. TCP Replay Attack 识别规则重写（原规则存在根本性错误）：
     旧规则：has_synack + pure_ack > 300 → 错误，有 SYN-ACK 说明服务端实际响应，
             不是盲回放；DupACK-Flood 等正常建连的大量 ACK 会误触发。
     新规则（两阶段）：
       阶段1（会话级）：收集 NOT has_synack（盲注入）+ 客户端有 PSH payload 的会话，
                        取 PSH payload 前64字节作指纹。
       阶段2（跨会话）：相同指纹来自 ≥ replay_min_src_ips（默认3）个不同 srcIP
                        且指向同一 (dst_ip, dport) → TCP-Replay-payload。
     新增配置项：tcp_state.replay_min_src_ips（默认3）
  2. parse_all() 新增 IP-in-IP（proto=4）透明拆封：
     遇到外层 IPv4 proto=4 时，自动解析内层 IPv4 头及上层协议（TCP/UDP/ICMP），
     并用内层字段覆盖 pkt 中的 src_ip/dst_ip/proto/tcp/udp/icmp，
     所有下游分类器无感知地处理内层流量。内层解析失败时保留外层 proto=4，
     由 classify_ip_flood() 兜底。
     配套工具：ACK快速重传/strip_ipip_vlan.py，可将 VLAN+IP-in-IP 封装的
     pcap 还原为内层纯 IPv4 帧，用于样本归档。
  2. ACK Flood 新增 DupACK-Flood 子类型：
     识别条件：纯 ACK 包（无 SYN/PSH/FIN/RST/URG/CWR/ECE）中，相同 ack_n 值出现
     ≥ 3 次的包占该目标 IP 全部纯 ACK 包的比例 > 80%，则归为 DupACK-Flood。
     攻击原理：攻击者对已建立连接反复发送相同 ACK 序号的纯 ACK 包（同一 ack_n
     重复 100-400 次），利用 TCP 快速重传机制（收到 3 个 dup ACK 即重传）强迫受害端
     反复重传数据，造成受害端出方向带宽激增和 CPU 耗尽。
     → TCP State Exhaustion Attack/DupACK-Flood/（区别于无会话状态的 ACK Flood）
  2. 实测场景：金融行业攻击，IP-in-IP 隧道（proto=4）承载，VLAN 标记，
     单目标 IP 单 TCP 端口，重复 ack_n 比例 99.9%（497/319 个唯一序号各重复 100-400 次）。

变更说明（v5.4）：
  1. 新增 IPv6 隧道洪泛分类器 classify_tunnel_flood()：
     检测两种封装形式的 IPv6 隧道洪泛攻击：
     (A) 6in4（proto=41）：
       子类（按内层 IPv6 next_hdr 区分）：
         6in4-TCP-Flood    → Volumetric Attack/IPv6 Tunnel Flood/6in4-TCP-Flood
         6in4-UDP-Flood    → Volumetric Attack/IPv6 Tunnel Flood/6in4-UDP-Flood
         6in4-ICMPv6-Flood → Volumetric Attack/IPv6 Tunnel Flood/6in4-ICMPv6-Flood
       攻击特征：将 IPv6 封装在 IPv4 proto=41 报文中绕过防火墙 ACL，饱和目标带宽。
     (B) Teredo（sport=3544，IPv6-over-UDP，RFC 4380）：
       子类（按内层 ICMPv6 type 区分）：
         Teredo-RA-Flood   → Volumetric Attack/IPv6 Tunnel Flood/Teredo-RA-Flood
         Teredo-NS-Flood   → Volumetric Attack/IPv6 Tunnel Flood/Teredo-NS-Flood
       攻击特征：通过 Teredo 隧道（Auth+Origin 双重头，XOR 混淆 IP/端口）注入伪造
       Router Advertisement（router_lifetime=0 + 垃圾前缀 ffff:ffff::/64），
       撤销受害者 IPv6 默认路由并触发反复路由表刷新，造成 IPv6 通信中断或 CPU 耗尽。
  2. 增强 classify_gre_flood()：新增内层协议识别，按 GRE 内层 EtherType 细分：
       GRE-IPv6-Flood  → Volumetric Attack/IP Flood/GRE-IPv6-Flood  （0x86DD）
       GRE-PPTP-Flood  → Volumetric Attack/IP Flood/GRE-PPTP-Flood  （0x880b，增强型GRE/PPTP）
       GRE-Flood       → Volumetric Attack/IP Flood/GRE Flood        （其余）
     分布式 GRE-PPTP-Flood 实测：100 个源 IP 打 1 个目标 IP。
  3. 新增模块级辅助函数 _parse_gre_proto() 和 _parse_teredo_offset()：
     _parse_gre_proto()      ：解析 GRE 头部 Protocol Type 字段（偏移 2~3B）
     _parse_teredo_offset()  ：解析 Teredo Auth+Origin 双重头，返回内层 IPv6 偏移
  4. HTTPS Client-Hello-FIN-Flood 新子类（上一版本遗留记录于此）：
     ClientHello 与 FIN 同包，攻击全周期仅需 SYN + ClientHello+FIN 共 2 个报文。
     → Application Attack/HTTPS/TLS Handshake Flood/Client-Hello-FIN-Flood

变更说明（v5.3）：
  1. DNS 放大 qtype 扩展：AXFR(252)/IXFR(251)/DNSKEY(48)/DS(43)/RRSIG(46)/TXT(16)
     新增 Query-AXFR / Query-DNSKEY / Query-TXT 子分类，配套 query_*_min 阈值
  2. DTLS 分类器完全重写（5 子类）：
     NullSession / ClientHello Flood / Fragment Exhaustion / State Exhaustion / CC Attack
     修正 ClientHello 判定（handshake_type==1，非 content_type==22），修正分片偏移量
  3. HTTPS 新增 HTTP/2 Rapid Reset 检测（CVE-2023-44487）：
     h2 ALPN + AppData + TCP RST + 会话时长 ≤ http2_rapid_reset_duration
  4. HTTPS Suspicious-HTTP2 增加 AppData 数量门槛（h2_suspicious_appdata_min）降低误报
  5. Bug 修复：
     - GET/POST/HEAD Flood 改为填充 cats，修复 Government 双写缺失
     - Client-Hello-Flood 改为会话级 f_app_data 判断，防止攻击者偶尔完成握手绕过检测
     - Browser-Emulation 从 dir_map 移除，修复运行时 KeyError 崩溃
     - HTTPS cats['Gov'] 静默丢弃修复，Gov 会话落入 CC 兜底并由 https_gov_pairs 双写
     - HTTP TCP-Segmentation-Evasion 重复 _add 调用修复
     - HTTP cats['Browser-Emulation'] 死代码声明清理
  6. 文档同步：DTLS/DNS/HTTPS 分类说明、目录结构、配置项全量更新

变更说明（v5.1）：
  1. UDP 反射识别原则强化（4 条原则）：
     原则1：UDP 反射优先级高于反射诱发（sport 匹配优先于 dport 匹配）
     原则2：反射诱发识别收紧——必须是标准 dport + request 报文，新增
             AMPLIFICATION_REQUEST_VALIDATORS 字典，各协议独立 request 校验：
             DNS(ANY only), NTP(MON_GETLIST), SNMP(GetBulk/Get), STUN(Binding Request),
             SSDP(M-SEARCH), CLDAP(searchRequest), Memcached(get/gets),
             Ubiquiti(4字节探测包), BACnet(Who-Is), WSD(Probe), CoAP(well-known)
             SIP 诱发限定为 INVITE/OPTIONS/REGISTER 方法；不再识别非标准端口的诱发报文
     原则3：反射响应识别分两类：固定端口协议按 sport+payload 校验，
             可变端口协议（SSDP 等）按 payload 内容识别；
             NTP mode=7 响应必须 R bit=1（response），修复请求/响应混淆；
             SSDP 响应 validator 收紧为 HTTP/1.1 200 OK + UPnP 特征（排除 M-SEARCH 请求）；
             UDP 反射识别优先级高于 UDP Flood
     原则4：各协议增加字符串特征识别（payload keyword fallback）：
             CLDAP, SSDP, SNMP, Memcached, CoAP, SIP, WSD, Ubiquiti
  2. classify_udp_reflection 移除 XX_{sport} 子类（无意义的未知端口分类）
  3. 文件名修正：SSDP_randomsport → SSDP-randomsport（统一用连字符）
  4. Large SYN 定义确认：payload > 0 字节即为 largeSYN（原文档描述 >100 有误）

变更说明（v5.0）：
  1. 所有检测阈值提取到配置文件 ddos_classifier.yaml，程序启动时动态加载。
     修改阈值无需改代码，重启生效。配置文件与脚本同目录，或通过 --config 指定。
  2. 文件名下标优化：首个文件不带 _0 后缀（dstIP_type_date.pcap），
     从第二个文件起才加 _1, _2 … 后缀。
  3. DNS Query Flood 修复：合法 DNS query（任意 qtype）不再误归 UDP Flood。
  4. HTTP Single URL 文件名后缀修正为 Single-URL。

变更说明（v4.52）：
  1. 全面兼容 IPv6：parse_all 解析 IPv6 头及扩展头，所有分类器自动在子目录插入
     IPv4/ 或 IPv6/ 层级（save 方法统一处理），文件名中的 dstIP 冒号替换为下划线。
  2. SYN Flood / SYN-ACK Flood 定义收紧：
     仅保留在该 dstIP+dport 上没有 ACK 报文跟进的会话的 SYN / SYN-ACK 包，
     即会话中每个报文都是单报文（无握手后续 ACK），确保是真正的泛洪。
  3. ACK Flood / FIN-ACK Flood / RST Flood 定义收紧：
     仅保留无法命中已建立会话（同一四元组下无 SYN 或 SYN-ACK 确立）的后续报文。

变更说明（v4.51）：
  1. DNS 目录重构：DNS Malformed → Application Attack/DNS/Malformed
                   DNS Query → Application Attack/DNS/DNS Query Flood
  2. 新增 DNS Response Flood：dport=53 & sport>1024 & QR=1 & ≥50包
     → Application Attack/DNS/DNS Response Flood，后缀 response
  3. HTTP Single URL：同 URL 重复请求 >5 次
     目录：Application Attack/HTTP/Single URL，后缀 Same-Request-PktLen
  3b. HTTPS Same Request PktLen：≥5 个 AppData 报文长度一致
     目录：Application Attack/HTTPS/Same Request PktLen，后缀 Same-Request-PktLen
  4. SYN-ACK Flood 独立目录：Volumetric Attack/TCP/SYN-ACK
  5. QUIC 短头部收紧：payload 前64字节字节种类≤2视为垃圾包，拒绝识别为 QUIC
  6. GRE Flood 目录：Volumetric Attack/IP Flood/GRE Flood，后缀 GRE-Flood
  7. 新增 IP Flood 分类器（非 GRE/TCP/UDP/ICMP 包，≥100）
     → Volumetric Attack/IP Flood/IP Flood，后缀 IP-Flood
  8. 新增 IP Fragment Flood（非 TCP/UDP/ICMP 分片包，≥100）
     → Volumetric Attack/IP Flood/IP Flood，后缀 Fragment
  9. DTLS-CC → Application Attack/DTLS/State Exhaustion Attack，后缀 State-exhaustion
 10. TLS Incomplete Session → Client Hello Flood
     → Application Attack/HTTPS/TLS Handshake Flood，后缀 Client-Hello-Flood
 11. TLS NullSession → Negotiation Abuse
     → Application Attack/HTTPS/TLS Handshake Flood，后缀 Negotiation-Abuse
 12. THC-SSL → Application Attack/HTTPS/TLS Handshake Flood（文件名不变）
 13. 删除 Multiple Hello 分类
 14. 修复 HTTP Other Method 误识别 Bug：Method 统一从 TCP 分段重组后的流中提取，
     不再从各分段包单独提取（防止分段 GET 后续片段被误判为 Other Method）

用法：
    python3 ddos_classifier.py <pcap文件或通配符> [选项]

示例：
    python3 ddos_classifier.py *.pcap
    python3 ddos_classifier.py /data/caps/*.pcap --output /data/output
    python3 ddos_classifier.py *.pcap --config whitelist.json
    python3 ddos_classifier.py *.pcap --http-ports 80,8080,8000 --https-ports 443,8443
    python3 ddos_classifier.py *.pcap --botnet-threshold 100 --slow-win 10

配置文件格式 (JSON)：
    {
        "whitelist_domains": ["www.yundun.com"],
        "whitelist_src_ip":  ["1.2.3.4"],
        "whitelist_dst_ip":  [],
        "whitelist_urls":    [],
        "dns_whitelist_domains": [],
        "dns_whitelist_src_ip":  [],
        "dns_whitelist_dst_ip":  []
    }
"""

import sys, os, re, glob, struct, argparse, collections, datetime, json, math, ipaddress
from pathlib import Path
try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# =============================================================================
# 配置加载（ddos_classifier.yaml，与脚本同目录或由 --config 指定）
# =============================================================================

def _load_config(config_path: str | None = None) -> dict:
    """加载 YAML 配置文件，返回配置 dict。
    找不到文件或 PyYAML 不可用时使用内置默认值。
    """
    default_path = Path(__file__).parent / 'ddos_classifier.yaml'
    path = Path(config_path) if config_path else default_path

    if _YAML_AVAILABLE and path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            cfg = _yaml.safe_load(f) or {}
        return cfg

    # 内置默认值（与 ddos_classifier.yaml 保持同步）
    return {
        'min_pkts': {
            'default': 20, 'udp_reflection': 100, 'amp_request': 50,
            'quic': 100, 'dns': 100, 'sip': 100, 'dtls_incomplete': 5,
            'fragment': 100, 'ip_flood': 100, 'botnet': 50,
        },
        'udp_flood': {
            'fixedsport_min_pkts': 500, 'garbage_one_pkt_ratio': 0.8,
            'garbage_src_ip_min': 5, 'garbage_len_variety_min': 5,
            'garbage_payload_unique_ratio': 0.8, 'highentropy_threshold': 6.5,
            'highentropy_flow_min_pkts': 5, 'random_sport_port_max': 10000,
        },
        'udp_reflection': {
            'srcip_concentrated_threshold': 50,
        },
        'slow_attack': {
            'zero_win_min': 3, 'small_win_min': 8, 'small_win_max': 10,
            'duration_min': 15.0, 'slow_win_threshold': 10,
        },
        'tcp_state': {
            'null_session_pure_ack_min': 300, 'l4cc_psh_ack_min': 300,
            # TCP-Replay-payload 配置（独立分类器 classify_tcp_replay）
            'replay_min_pkts':           10,   # 单会话内最少 ACK+payload 包数
            'replay_min_src_ips':         3,   # 相同 payload 指纹最少来自几个不同 srcIP
            'replay_seq_growth_ratio':  0.8,   # seq 严格递增比例门槛（区分随机注入）
        },
        'http': {
            'min_sessions': 5, 'get_flood_min_reqs': 10,
            'post_flood_min_reqs': 2, 'head_flood_min_reqs': 2,
            'other_method_min_reqs': 2, 'single_url_min_reqs': 5,
            'multiple_url_min_reqs': 10, 'bigresource_min_reqs': 10,
            'bigresource_ack_growth': 51200,
            'slow_post_psh_min': 5, 'slow_post_psh_max_len': 45,
            'slow_headers_psh_min': 3, 'slow_headers_psh_max_len': 45,
            'tcp_seg_evasion_min': 10, 'param_pollution_query_len': 500,
            'browser_emulation_min_reqs': 3, 'browser_emulation_min_sub': 2,
            'multiple_method_min_pkt_len': 100,
            'random_url_min_reqs': 5, 'random_url_random_ratio': 0.5,
        },
        'https': {
            'min_sessions': 5, 'same_pkt_len_min_pkts': 5,
            'same_pkt_len_consistency': 0.8,   # AppData 长度一致性阈值（≥80% 触发）
            'bigresource_min_sessions': 10, 'client_hello_min': 2,
            'ccs_min': 2, 'null_session_pure_ack': 300, 'tls_max_record_len': 16384,
            'http2_rapid_reset_duration': 5.0,  # Rapid Reset 最大会话时长（秒），超过视为正常连接
            'h2_suspicious_appdata_min': 1,     # Suspicious-HTTP2：客户端 AppData TLS record 数门槛
                                                # （仅做"真实TLS会话"过滤，默认1=任意AppData即可）
            'h2_suspicious_min_sessions': 2,    # Suspicious-HTTP2 兜底：srcIP 完整会话数 >= 此值即可触发
        },
        'quic': {
            'min_udp_length': 21, 'sport_min': 1024, 'conn_id_flood_ratio': 0.9,
        },
        'ja4': {
            'botnet_min_src_ips': 10,   # 同一 JA4 → 同一 dstIP 出现的不同 srcIP 数 ≥ 此值 → JA4-Botnet
            'enable_metadata_log': True, # 是否将每个 dst_ip 观测到的 JA4 汇总写入 ja4_summary.json
        },
        'dns': {
            'malformed_min': 10, 'random_sub_min': 10, 'nxdomain_min': 50,
            'samesubnet_min': 10, 'dns_sec_min': 50, 'query_any_min': 50,
            'query_opt_rr_min': 50, 'query_min': 50, 'opt_rr_udp_size': 1500,
            'response_min': 50, 'mdns_qdcount_max': 10,
            'query_axfr_min': 10,    # AXFR/IXFR 区域传输：正常流量几乎没有，阈值低
            'query_dnskey_min': 20,  # DNSKEY/DS/RRSIG DNSSEC 记录放大
            'query_txt_min': 50,     # TXT 记录放大（SPF/DMARC 等）
        },
        'abnormal_url': {
            'garbled_non_print_min': 3, 'garbled_non_print_ratio': 0.2,
        },
        'cli_defaults': {
            'http_ports': [80, 8080], 'https_ports': [443, 8443],
            'botnet_threshold': 50, 'slow_win_threshold': 10,
        },
    }


# 全局配置对象（main() 里用 --config 覆盖后重载）
CFG = _load_config()

def _c(*keys, default=None):
    """快捷读取嵌套配置：_c('http', 'min_sessions') → CFG['http']['min_sessions']"""
    v = CFG
    for k in keys:
        if not isinstance(v, dict):
            return default
        v = v.get(k, default)
    return v

# =============================================================================
# 常量
# =============================================================================

# ── UDP 反射端口 ──────────────────────────────────────────────────────────────
REFLECTION_PORTS_UDP = {
    7:'Echo', 9:'Discard', 17:'QOTD', 19:'Chargen', 53:'DNS',
    88:'Kerberos', 111:'Portmap', 123:'NTP', 137:'NetBIOS-NS',
    138:'NetBIOS-DGM', 161:'SNMP', 389:'CLDAP', 443:'QUIC',
    500:'IKE', 520:'RIP', 623:'IPMI', 1194:'OpenVPN', 1434:'MSSQL',
    1701:'L2TP', 1900:'SSDP', 2123:'GTPv1', 3283:'Apple-ARD',
    3386:'GTP', 3478:'STUN', 3479:'STUN', 3702:'WSD',
    4433:'DTLS', 4500:'IKE-NAT', 4739:'IPFIX',
    5004:'RTCP', 5005:'RTCP',
    5060:'SIP', 5246:'CAPWAP', 5247:'CAPWAP', 5353:'mDNS',
    5683:'CoAP', 5684:'DTLS', 6881:'BitTorrent', 10001:'Ubiquiti',
    11211:'Memcached', 17500:'Dropbox', 25565:'Minecraft',
    27015:'Steam', 27960:'Quake', 30718:'Lantronix',
    32414:'Plex', 47808:'BACnet', 51820:'WireGuard',
}

# ── TCP 反射端口 ──────────────────────────────────────────────────────────────
REFLECTION_PORTS_TCP = {
    21:'FTP', 22:'SSH', 23:'Telnet', 53:'DNS', 69:'TFTP',
    80:'HTTP', 81:'HTTP-Alt', 443:'HTTPS', 445:'SMB',
    689:'NMAP', 1433:'MSSQL', 1723:'PPTP', 1900:'SSDP',
    2601:'Zebra', 3306:'MySQL', 3389:'RDP', 5060:'SIP',
    7547:'TR-069', 8080:'HTTP-Proxy', 30010:'Unknown',
    58000:'Unknown',
}

# ── HTTP Methods ──────────────────────────────────────────────────────────────
HTTP_METHODS     = {b'GET',b'POST',b'HEAD',b'PUT',b'DELETE',
                    b'OPTIONS',b'PATCH',b'TRACE',b'CONNECT'}
COMMON_METHODS   = {b'GET',b'POST',b'HEAD'}
UNCOMMON_METHODS = HTTP_METHODS - COMMON_METHODS

# ── 已知工具 UA ───────────────────────────────────────────────────────────────
TOOL_UA_PATTERNS = [
    'nws_tc', 'sonar_probe', 'go-http-client', 'python-requests',
    'curl/', 'wget/', 'libwww-perl', 'masscan', 'zgrab', 'nikto',
    'sqlmap', 'nmap scripting', 'httperf', 'ab/', 'wrk/',
]

# ── SIP 端口 ──────────────────────────────────────────────────────────────────
SIP_PORTS = {5060, 5061}

# ── DTLS 端口 ─────────────────────────────────────────────────────────────────
# 4433=DTLS 标准  5684=CoAP-over-DTLS  443=DTLS/QUIC 混用（QUIC 优先处理）
# 3478/5349(WebRTC STUN) 由 classify_udp_reflection 处理，不放入此集合
DTLS_PORTS = {4433, 5684, 443}

# ── DNS 端口 ──────────────────────────────────────────────────────────────────
DNS_PORT = 53

# ── 合法 TCP Flag 组合 ────────────────────────────────────────────────────────
# flags byte: URG ACK PSH RST SYN FIN = bits 5-0
VALID_FLAG_COMBOS = {
    0x02,  # SYN
    0x12,  # SYN-ACK
    0x10,  # ACK
    0x18,  # PSH-ACK
    0x11,  # FIN-ACK
    0x01,  # FIN
    0x04,  # RST
    0x14,  # RST-ACK
    0x19,  # FIN-PSH-ACK
    # ECN 相关合法组合
    0x02 | 0x40 | 0x80,  # SYN-ECE-CWR（ECN 协商）
    0x18 | 0x40,         # PSH-ACK-ECE
    0x18 | 0x80,         # PSH-ACK-CWR
    0x10 | 0x40,         # ACK-ECE
    0x10 | 0x80,         # ACK-CWR
    0x12 | 0x40,         # SYN-ACK-ECE
    0x02 | 0x10,         # SYN-ACK（重复保留）
}


# =============================================================================
# pcap 读写
# =============================================================================

PCAP_GLOBAL_HEADER = (
    b'\xd4\xc3\xb2\xa1'                          # LE magic
    + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1)  # ver / tz / sig / snap / ETHERNET
)


def read_pcap(filepath):
    """返回 list of (ts_float, raw_bytes)，自动识别链路层类型。
    支持：
      linktype=1   Ethernet（最常见）
      linktype=101 Raw IP（Linux loopback 等）
      linktype=228 Raw IPv4
      linktype=229 Raw IPv6
    对非以太网链路类型，在 raw_bytes 前插入 14 字节伪以太网头，
    使 parse_ethernet / parse_all 无需修改即可正常处理。
    """
    # 伪以太网头：12字节零MAC + 2字节EtherType
    FAKE_ETH_IPV4 = bytes(12) + bytes([0x08, 0x00])  # EtherType=IPv4
    FAKE_ETH_IPV6 = bytes(12) + bytes([0x86, 0xDD])  # EtherType=IPv6

    packets = []
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4:
                return packets
            if magic == bytes([0xd4, 0xc3, 0xb2, 0xa1]):
                endian = '<'
            elif magic == bytes([0xa1, 0xb2, 0xc3, 0xd4]):
                endian = '>'
            else:
                return packets
            # 读全局头剩余20字节，提取 linktype
            rest = f.read(20)
            if len(rest) < 20:
                return packets
            # 全局头布局：magic(4) + version_major(2) + version_minor(2)
            #             + thiszone(4) + sigfigs(4) + snaplen(4) + network(4)
            linktype = struct.unpack(endian + 'I', rest[16:20])[0]

            while True:
                rec = f.read(16)
                if len(rec) < 16:
                    break
                ts_s, ts_us, incl, orig = struct.unpack(endian + 'IIII', rec)
                data = f.read(incl)
                if len(data) < incl:
                    break
                # 非以太网链路类型：补伪以太网头，使后续 parse_ethernet 正常解析
                if linktype == 1:
                    raw = data                          # 标准以太网，直接用
                elif linktype == 228:
                    raw = FAKE_ETH_IPV4 + data          # Raw IPv4
                elif linktype == 229:
                    raw = FAKE_ETH_IPV6 + data          # Raw IPv6
                elif linktype == 101:
                    # Raw IP：根据首字节 IP 版本选择头部
                    if data and (data[0] >> 4) == 6:
                        raw = FAKE_ETH_IPV6 + data
                    else:
                        raw = FAKE_ETH_IPV4 + data
                else:
                    # 其他链路类型：原样传入，parse_ethernet 失败则跳过
                    raw = data
                packets.append((ts_s + ts_us / 1e6, raw))
    except Exception as e:
        print(f'  [WARN] 读取失败 {filepath}: {e}')
    return packets


def write_pcap(filepath, packets):
    """packets: [(ts_float, raw_bytes), ...]"""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, data in sorted(packets, key=lambda x: x[0]):
            ts_s  = int(ts)
            ts_us = int((ts - ts_s) * 1_000_000)
            incl  = len(data)
            f.write(struct.pack('<IIII', ts_s, ts_us, incl, incl))
            f.write(data)


# =============================================================================
# 文件名管理（跨运行持久化序号）
# =============================================================================

class FileNamer:
    _SEQ_RE = re.compile(r'^(.+)_(\d+)\.pcap$', re.IGNORECASE)

    def __init__(self, output_root: str):
        self.output_root = Path(output_root)
        self._next: dict = {}
        self._scan_existing()

    def _scan_existing(self):
        if not self.output_root.exists():
            return
        for pcap_path in self.output_root.rglob('*.pcap'):
            try:
                rel   = pcap_path.relative_to(self.output_root)
                parts = rel.parts
                if len(parts) < 2:
                    continue
                subdir = str(Path(*parts[:-1]))
                fname  = parts[-1]
                m = self._SEQ_RE.match(fname)
                if m:
                    # 带下标：dstIP_suffix_date_N.pcap → key=base, next=N+1
                    key = (subdir, m.group(1))
                    seq = int(m.group(2))
                    if self._next.get(key, 0) <= seq:
                        self._next[key] = seq + 1
                elif fname.endswith('.pcap'):
                    # 不带下标：dstIP_suffix_date.pcap → key=base, next=1（下一个用_1）
                    base = fname[:-5]  # 去掉 .pcap
                    key  = (subdir, base)
                    if self._next.get(key, 0) == 0:
                        self._next[key] = 1
            except Exception:
                continue

    def get_path(self, subdir: str, dst_ip: str, suffix: str, date_str: str) -> str:
        base     = f'{dst_ip}_{suffix}_{date_str}'
        key      = (subdir, base)
        seq      = self._next.get(key, 0)
        dirpath  = self.output_root / subdir
        # seq=0 时不带下标（dstIP_suffix_date.pcap）
        # seq>=1 时才加下标（dstIP_suffix_date_1.pcap，dstIP_suffix_date_2.pcap …）
        filepath = dirpath / (f'{base}.pcap' if seq == 0 else f'{base}_{seq}.pcap')
        while filepath.exists():
            seq += 1
            filepath = dirpath / (f'{base}.pcap' if seq == 0 else f'{base}_{seq}.pcap')
        self._next[key] = seq + 1
        return str(filepath)


# =============================================================================
# 协议解析
# =============================================================================

def parse_ethernet(data):
    if len(data) < 14:
        return None
    et = struct.unpack('>H', data[12:14])[0]
    offset = 14
    while et == 0x8100:  # VLAN
        if len(data) < offset + 4:
            return None
        et = struct.unpack('>H', data[offset+2:offset+4])[0]
        offset += 4
    return et, data[offset:]


def parse_ip(payload):
    if len(payload) < 20 or (payload[0] >> 4) != 4:
        return None
    ihl       = (payload[0] & 0xF) * 4
    total_len = struct.unpack('>H', payload[2:4])[0]
    flags_frag = struct.unpack('>H', payload[6:8])[0]
    frag_off  = flags_frag & 0x1FFF
    more_frag = bool(flags_frag & 0x2000)
    proto     = payload[9]
    ttl       = payload[8]
    checksum  = struct.unpack('>H', payload[10:12])[0]
    src_ip    = '.'.join(str(b) for b in payload[12:16])
    dst_ip    = '.'.join(str(b) for b in payload[16:20])
    body      = payload[ihl: min(total_len, len(payload))]
    return dict(
        proto=proto, src_ip=src_ip, dst_ip=dst_ip,
        ihl=ihl, total_len=total_len, ttl=ttl,
        checksum=checksum, payload=body,
        frag_off=frag_off, more_frag=more_frag,
        is_fragment=(frag_off > 0 or more_frag),
        raw_ip=payload,
    )


def parse_ipv6(payload):
    """解析 IPv6 基础头及常见扩展头，返回与 parse_ip 兼容的字典。
    支持扩展头链：Hop-by-Hop(0), Routing(43), Fragment(44),
                  Destination(60), No-Next-Header(59)。
    遇到 Fragment 扩展头时设置 is_fragment=True。
    """
    if len(payload) < 40 or (payload[0] >> 4) != 6:
        return None
    payload_len = struct.unpack('>H', payload[4:6])[0]
    next_hdr    = payload[6]
    # hop_limit = payload[7]  # TTL 等价字段
    src_ip = _fmt_ipv6(payload[8:24])
    dst_ip = _fmt_ipv6(payload[24:40])
    body   = payload[40:]  # 扩展头 + 上层协议数据

    # 遍历扩展头
    is_fragment = False
    frag_off    = 0
    more_frag   = False
    EXT_HDRS    = {0, 43, 60}  # Hop-by-Hop, Routing, Destination

    while next_hdr in EXT_HDRS:
        if len(body) < 8:
            return None
        next_hdr = body[0]
        ext_len  = (body[1] + 1) * 8   # 单位：8字节（含首个8字节）
        body     = body[ext_len:]

    if next_hdr == 44:   # Fragment 扩展头
        if len(body) < 8:
            return None
        frag_field = struct.unpack('>H', body[2:4])[0]
        frag_off   = frag_field >> 3
        more_frag  = bool(frag_field & 0x0001)
        is_fragment = (frag_off > 0 or more_frag)
        next_hdr   = body[0]
        body       = body[8:]

    if next_hdr == 59:   # No Next Header
        body = b''

    return dict(
        proto=next_hdr, src_ip=src_ip, dst_ip=dst_ip,
        ihl=40, total_len=40 + payload_len, ttl=payload[7],
        checksum=0,
        payload=body,
        frag_off=frag_off, more_frag=more_frag,
        is_fragment=is_fragment,
        raw_ip=payload,
    )


def _fmt_ipv6(b16: bytes) -> str:
    """将 16 字节转为标准 IPv6 字符串（含 :: 压缩）。"""
    import ipaddress
    return str(ipaddress.IPv6Address(b16))


def parse_tcp(body):
    if len(body) < 20:
        return None
    sport    = struct.unpack('>H', body[0:2])[0]
    dport    = struct.unpack('>H', body[2:4])[0]
    seq      = struct.unpack('>I', body[4:8])[0]
    ack_n    = struct.unpack('>I', body[8:12])[0]
    flags    = body[13]
    win_size = struct.unpack('>H', body[14:16])[0]
    checksum = struct.unpack('>H', body[16:18])[0]
    urg_ptr  = struct.unpack('>H', body[18:20])[0]
    hl       = max(20, ((body[12] >> 4) & 0xF) * 4)
    options  = body[20:hl] if hl > 20 else b''
    data     = body[hl:] if hl <= len(body) else b''
    return dict(
        sport=sport, dport=dport, seq=seq, ack_n=ack_n,
        flags=flags, win_size=win_size, checksum=checksum,
        urg_ptr=urg_ptr, data_offset=hl,
        options=options, payload=data,
        SYN=bool(flags & 0x02), ACK=bool(flags & 0x10),
        PSH=bool(flags & 0x08), FIN=bool(flags & 0x01),
        RST=bool(flags & 0x04), URG=bool(flags & 0x20),
        ECE=bool(flags & 0x40), CWR=bool(flags & 0x80),
    )


def parse_tcp_wscale(options: bytes) -> int:
    """从 TCP Options 字节中提取 Window Scale 值（Kind=3）。
    返回 wscale 整数（0-14），未找到则返回 0（Multiplier=1，即不缩放）。
    TCP Options 格式：
      Kind=0  (EOL)  : 1字节，结束
      Kind=1  (NOP)  : 1字节，填充
      Kind=2  (MSS)  : 4字节，Kind+Len+Value(2)
      Kind=3  (WS)   : 3字节，Kind+Len+Value(1)
      Kind=4  (SACK) : 2字节，Kind+Len
      Kind=8  (TS)   : 10字节，Kind+Len+Value(8)
    """
    pos = 0
    while pos < len(options):
        kind = options[pos]
        if kind == 0:          # EOL
            break
        if kind == 1:          # NOP（单字节，无长度字段）
            pos += 1
            continue
        if pos + 1 >= len(options):
            break
        length = options[pos + 1]
        if length < 2 or pos + length > len(options):
            break
        if kind == 3:          # Window Scale
            if length == 3:
                wscale = options[pos + 2]
                # RFC 7323：wscale 合法范围 0-14，超出按14处理
                return min(wscale, 14)
            break
        pos += length
    return 0


def parse_udp(body):
    if len(body) < 8:
        return None
    sport  = struct.unpack('>H', body[0:2])[0]
    dport  = struct.unpack('>H', body[2:4])[0]
    length = struct.unpack('>H', body[4:6])[0]
    return dict(sport=sport, dport=dport, length=length, payload=body[8:])


def parse_icmp(body):
    if len(body) < 4:
        return None
    return dict(type=body[0], code=body[1], payload=body[4:])


def _parse_gre_proto(data: bytes):
    """从 GRE 字节流提取内层 EtherType（Protocol Type 字段）。
    标准 GRE（RFC 2784）和增强型 GRE（RFC 2637 / PPTP）的 Protocol Type 均位于
    偏移 2~3 字节处，可直接读取。
    返回 int（如 0x86DD=IPv6, 0x880b=PPP, 0x0800=IPv4），失败返回 None。
    """
    if len(data) < 4:
        return None
    return struct.unpack_from('>H', data, 2)[0]


def _parse_teredo_offset(data: bytes) -> int:
    """解析 Teredo 头部，返回内层 IPv6 报文在 UDP payload 中的起始偏移。

    Teredo 数据包结构（RFC 4380）：
      [Auth 头（可选）] [Origin 头（可选）] IPv6 报文

      Auth 头   : indicator 0x00 0x01
                  + id_len(1B) + auth_len(1B)
                  + client_id(id_len B) + auth_value(auth_len B)
                  + nonce(8B) + confirmation(1B)
      Origin 头 : indicator 0x00 0x00
                  + obfuscated_port(2B, XOR 0xFFFF)
                  + obfuscated_ip(4B, XOR 0xFF 每字节)

    两个头可同时出现（先 Auth 后 Origin）。
    """
    off = 0
    n   = len(data)
    # Auth header
    if n >= 4 and data[0] == 0x00 and data[1] == 0x01:
        id_len   = data[2]
        auth_len = data[3]
        off = 4 + id_len + auth_len + 8 + 1  # indicator(2)+lens(2)+id+auth+nonce(8)+confirm(1)
    # Origin indication header（可在 Auth 之后）
    if off + 2 <= n and data[off] == 0x00 and data[off + 1] == 0x00:
        off += 8  # indicator(2) + port(2) + ip(4)
    return off


def reassemble_tcp_payload(tl: list) -> tuple:
    """按 TCP seq 号对会话内所有 data 包进行分段重组，返回 (reassembled_bytes, ack_segmented)。

    ack_segmented=True 表示该会话存在分段传输行为：
      即应用层数据被拆分为多个 PSH 包，每包 payload < 50 字节（ACK segmentation 特征）。

    重组算法：
      1. 收集所有含 payload 的包，按 seq 排序
      2. 以第一个数据包的 seq 为基准，依次填充字节流
      3. 重叠或乱序包按实际 seq 偏移写入，不重复
      4. 最大重组长度限制为 65535 字节（防止内存放大）
    """
    MAX_REASM = 65535
    data_pkts = [(t['seq'], t['payload']) for t in tl
                 if t['payload'] and not t['SYN'] and not t['RST']]
    if not data_pkts:
        return b'', False

    data_pkts.sort(key=lambda x: x[0])
    base_seq = data_pkts[0][0]

    buf = bytearray()
    for seq, payload in data_pkts:
        offset = (seq - base_seq) & 0xFFFFFFFF   # 处理 seq 回绕
        # 跳过 seq 回绕导致的超大偏移（异常包）
        if offset > MAX_REASM:
            continue
        end = offset + len(payload)
        if end > MAX_REASM:
            payload = payload[:MAX_REASM - offset]
            end = MAX_REASM
        if end > len(buf):
            buf.extend(b'\x00' * (end - len(buf)))
        buf[offset:offset + len(payload)] = payload

    # ack_segmentation 判定：≥2个 PSH 包且所有 PSH payload 均 < 50 字节
    psh_payloads = [t['payload'] for t in tl if t['PSH'] and t['payload']]
    ack_segmented = (
        len(psh_payloads) >= 2 and
        all(len(pl) < 50 for pl in psh_payloads)
    )
    return bytes(buf), ack_segmented


# =============================================================================
# 全量包解析
# =============================================================================

def parse_all(raw_packets):
    out = []
    for ts, raw in raw_packets:
        frame = parse_ethernet(raw)
        if frame is None:
            continue
        et, net = frame

        pkt = dict(ts=ts, raw=raw, et=et,
                   src_ip=None, dst_ip=None, proto=None,
                   sport=0, dport=0,
                   tcp=None, udp=None, icmp=None, ip=None,
                   ip_ver=4)   # 4 or 6，默认 4，IPv6 解析时覆盖

        if et == 0x0800:  # IPv4
            ip = parse_ip(net)
            if ip is None:
                continue
            pkt['ip']     = ip
            pkt['src_ip'] = ip['src_ip']
            pkt['dst_ip'] = ip['dst_ip']
            pkt['proto']  = ip['proto']
            pkt['ip_ver'] = 4

            if ip['frag_off'] > 0:
                # 非首片分片（frag_off>0），无上层头部，直接记录
                out.append(pkt)
                continue
            # 首片（frag_off==0，可能 more_frag=True）仍可解析上层协议

            if ip['proto'] == 6:    # TCP
                t = parse_tcp(ip['payload'])
                if t is None:
                    continue
                pkt['sport'] = t['sport']
                pkt['dport'] = t['dport']
                pkt['tcp']   = t
            elif ip['proto'] == 17: # UDP
                u = parse_udp(ip['payload'])
                if u is None:
                    continue
                pkt['sport'] = u['sport']
                pkt['dport'] = u['dport']
                pkt['udp']   = u
            elif ip['proto'] == 1:  # ICMP
                ic = parse_icmp(ip['payload'])
                if ic is None:
                    continue
                pkt['icmp'] = ic
            elif ip['proto'] == 47: # GRE
                pass  # GRE: just record proto
            elif ip['proto'] == 4:  # IP-in-IP：拆封内层 IPv4
                inner = parse_ip(ip['payload'])
                if inner is not None:
                    # 用内层 IP 覆盖外层字段，下游分类器透明看到内层流量
                    pkt['ip']     = inner
                    pkt['src_ip'] = inner['src_ip']
                    pkt['dst_ip'] = inner['dst_ip']
                    pkt['proto']  = inner['proto']
                    # ip_ver 保持 4（内层也是 IPv4）
                    if inner['frag_off'] > 0:
                        out.append(pkt)
                        continue
                    if inner['proto'] == 6:    # 内层 TCP
                        t = parse_tcp(inner['payload'])
                        if t is not None:
                            pkt['sport'] = t['sport']
                            pkt['dport'] = t['dport']
                            pkt['tcp']   = t
                    elif inner['proto'] == 17: # 内层 UDP
                        u = parse_udp(inner['payload'])
                        if u is not None:
                            pkt['sport'] = u['sport']
                            pkt['dport'] = u['dport']
                            pkt['udp']   = u
                    elif inner['proto'] == 1:  # 内层 ICMP
                        ic = parse_icmp(inner['payload'])
                        if ic is not None:
                            pkt['icmp'] = ic
                    # 其余内层协议直接记录 proto，由 classify_ip_flood 兜底
                # inner 解析失败则保留外层 proto=4，classify_ip_flood 兜底

        elif et == 0x86DD:  # IPv6
            ip6 = parse_ipv6(net)
            if ip6 is None:
                continue
            pkt['ip']     = ip6
            pkt['src_ip'] = ip6['src_ip']
            pkt['dst_ip'] = ip6['dst_ip']
            pkt['proto']  = ip6['proto']
            pkt['ip_ver'] = 6

            if ip6['is_fragment'] and ip6['frag_off'] > 0:
                out.append(pkt)
                continue

            if ip6['proto'] == 6:    # TCP
                t = parse_tcp(ip6['payload'])
                if t is None:
                    continue
                pkt['sport'] = t['sport']
                pkt['dport'] = t['dport']
                pkt['tcp']   = t
            elif ip6['proto'] == 17: # UDP
                u = parse_udp(ip6['payload'])
                if u is None:
                    continue
                pkt['sport'] = u['sport']
                pkt['dport'] = u['dport']
                pkt['udp']   = u
            elif ip6['proto'] == 58: # ICMPv6
                ic = parse_icmp(ip6['payload'])  # 结构相同，type/code/payload
                if ic is None:
                    continue
                pkt['icmp'] = ic
            elif ip6['proto'] == 47: # GRE
                pass
        else:
            continue

        out.append(pkt)
    return out


def tcp_sessions_by_key(parsed):
    """双向 TCP 会话重组：(min_ep, max_ep) -> [pkt,...]
    
    将同一四元组的正向和反向包归入同一会话 key，解决单向抓包（入向）
    看不到 SYN（出方向）的问题。
    
    key 规则：将两个端点字符串 "IP:port" 排序后取小者为 key[0]，大者为 key[1]，
    保证 (A→B) 和 (B→A) 用同一个 key。
    
    同时在每个包上附加 direction 字段：
      'c2s'：客户端→服务端（发起 SYN 的方向，或 dport 是已知服务端口）
      's2c'：服务端→客户端（反向）
    
    注意：合并后会话列表可能包含双向包，classify 函数需要正确区分方向。
    """
    d = collections.defaultdict(list)
    for p in parsed:
        if p['proto'] == 6 and p['tcp']:
            ep1 = f"{p['src_ip']}:{p['sport']}"
            ep2 = f"{p['dst_ip']}:{p['dport']}"
            key = (min(ep1, ep2), max(ep1, ep2))
            d[key].append(p)
    return d


def _session_endpoints(key):
    """从双向 session key 解析两个端点字符串。"""
    return key[0], key[1]


def _identify_client(session_pkts):
    """从会话包列表中识别客户端 IP（发起 SYN 的一侧）。
    优先用 SYN 包判断；无 SYN 则用 SYN-ACK 反推（SYN-ACK 的 dst 是客户端）；
    再无则用 dport 启发式（低端口侧更可能是服务端）。
    返回 (client_ip, client_port, server_ip, server_port)。
    """
    for p in session_pkts:
        t = p['tcp']
        if t['SYN'] and not t['ACK']:
            return p['src_ip'], p['sport'], p['dst_ip'], p['dport']
    for p in session_pkts:
        t = p['tcp']
        if t['SYN'] and t['ACK']:
            # SYN-ACK 的 src 是服务端，dst 是客户端
            return p['dst_ip'], p['dport'], p['src_ip'], p['sport']
    # 启发式：低端口侧为服务端
    p0 = session_pkts[0]
    if p0['dport'] < p0['sport']:
        return p0['src_ip'], p0['sport'], p0['dst_ip'], p0['dport']
    return p0['dst_ip'], p0['dport'], p0['src_ip'], p0['sport']


def dedup_to_pairs(pkts):
    seen = {}
    for p in pkts:
        k = (p['ts'], p['raw'])
        if k not in seen:
            seen[k] = (p['ts'], p['raw'])
    return list(seen.values())


# =============================================================================
# 工具函数
# =============================================================================

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    ctr = collections.Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in ctr.values())


def ip_to_int(ip_str):
    try:
        return struct.unpack('>I', bytes(int(x) for x in ip_str.split('.')))[0]
    except Exception:
        return 0


def same_subnet_24(ip1, ip2):
    """IPv4 时比较 /24 网段，IPv6 时比较 /48 前缀（前6字节）。"""
    if ':' in ip1 or ':' in ip2:
        # IPv6：比较前6字节（/48）
        try:
            import ipaddress
            n1 = ipaddress.IPv6Address(ip1).packed[:6]
            n2 = ipaddress.IPv6Address(ip2).packed[:6]
            return n1 == n2
        except Exception:
            return False
    return ip_to_int(ip1) >> 8 == ip_to_int(ip2) >> 8


def calc_tcp_checksum(src_ip, dst_ip, tcp_data):
    """计算 TCP checksum（用于 malformed 检测）"""
    try:
        src = bytes(int(x) for x in src_ip.split('.'))
        dst = bytes(int(x) for x in dst_ip.split('.'))
        pseudo = src + dst + b'\x00\x06' + struct.pack('>H', len(tcp_data))
        data   = pseudo + tcp_data
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack('>H', data[i:i+2])[0] for i in range(0, len(data), 2))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF
    except Exception:
        return -1


# =============================================================================
# 白名单
# =============================================================================

class Whitelist:
    def __init__(self, cfg: dict):
        self.domains     = [d.lower() for d in cfg.get('whitelist_domains', [])]
        self.src_ips     = set(cfg.get('whitelist_src_ip', []))
        self.dst_ips     = set(cfg.get('whitelist_dst_ip', []))
        self.urls        = [u.lower() for u in cfg.get('whitelist_urls', [])]
        self.dns_domains = [d.lower() for d in cfg.get('dns_whitelist_domains', [])]
        self.dns_src_ips = set(cfg.get('dns_whitelist_src_ip', []))
        self.dns_dst_ips = set(cfg.get('dns_whitelist_dst_ip', []))

    def hit_http(self, src_ip, dst_ip, host='', url=''):
        if src_ip in self.src_ips or dst_ip in self.dst_ips:
            return True
        h = host.lower()
        if any(d in h for d in self.domains):
            return True
        u = url.lower()
        if any(w in u for w in self.urls):
            return True
        return False

    def hit_dns(self, src_ip, dst_ip, domain=''):
        if src_ip in self.dns_src_ips or dst_ip in self.dns_dst_ips:
            return True
        d = domain.lower()
        if any(w in d for w in self.dns_domains):
            return True
        return False


DEFAULT_WHITELIST = {
    'whitelist_domains':    ['www.yundun.com'],
    'whitelist_src_ip':     [],
    'whitelist_dst_ip':     [],
    'whitelist_urls':       [],
    'dns_whitelist_domains':[],
    'dns_whitelist_src_ip': [],
    'dns_whitelist_dst_ip': [],
}


# =============================================================================
# HTTP / TLS 应用层解析辅助
# =============================================================================

def extract_http_methods(payload: bytes):
    if not payload:
        return []
    found = []
    for m in HTTP_METHODS:
        pos = 0
        while True:
            idx = payload.find(m, pos)
            if idx < 0:
                break
            after = idx + len(m)
            if after < len(payload) and payload[after:after+1] in (b' ', b'\t'):
                found.append(m.decode())
            pos = idx + 1
    return found


def parse_http_request(payload: bytes):
    """返回 {method, url, host, ua, content_length, has_range, headers_count, has_end, has_proxy}"""
    result = dict(method='', url='', host='', ua='',
                  content_length=0, has_range=False,
                  headers_count=0, has_end=False, has_proxy=False)
    # 常见代理头（小写匹配）
    PROXY_HEADERS = (
        'x-forwarded-for:',
        'x-forwarded-host:',
        'x-forwarded-proto:',
        'x-forwarded-port:',
        'x-real-ip:',
        'x-originating-ip:',
        'x-remote-ip:',
        'x-remote-addr:',
        'x-client-ip:',
        'via:',
        'forwarded:',
        'proxy-authorization:',
        'proxy-connection:',
        'client-ip:',
        'true-client-ip:',
        'cf-connecting-ip:',        # Cloudflare
        'x-cluster-client-ip:',
        'x-coming-from:',
        'x-original-url:',
        'x-rewrite-url:',
    )
    try:
        text = payload.decode('utf-8', 'replace')
        lines = text.replace('\r\n', '\n').split('\n')
        if not lines:
            return result
        parts = lines[0].split(' ')
        if len(parts) >= 2:
            result['method'] = parts[0]
            result['url']    = parts[1]
        for line in lines[1:]:
            if line == '':
                result['has_end'] = True
                break
            result['headers_count'] += 1
            ll = line.lower()
            if ll.startswith('host:'):
                result['host'] = line[5:].strip()
            elif ll.startswith('user-agent:'):
                result['ua'] = line[11:].strip()
            elif ll.startswith('content-length:'):
                try:
                    result['content_length'] = int(line[15:].strip())
                except Exception:
                    pass
            elif ll.startswith('range:'):
                result['has_range'] = True
            if not result['has_proxy'] and any(ll.startswith(ph) for ph in PROXY_HEADERS):
                result['has_proxy'] = True
    except Exception:
        pass
    return result


def is_ip_address(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except Exception:
        return False


def _is_param_pollution(url: str, length_threshold: int = 500) -> bool:
    """HTTP Parameter Pollution 检测：查询字符串超长 + 真正的污染结构特征。
    仅靠长度会误杀含 URL 编码中文/路径的正常请求（如搜索追踪 API）。
    需同时满足长度条件 AND 至少一项 HPP 结构特征：
      1. 重复参数名：?id=1&id=2（排除合法数组传参 name[]=v 模式）
      2. 值中含编码分隔符注入：%26（&）或 %3D（=）在值内部非末尾位置
         注：%3D 仅在中间位置才算注入，末尾 %3D/%3D%3D 是 Base64 padding 不算
      3. 参数数量异常多（≥15个不同参数名且总长超过阈值）
    """
    if '?' not in url:
        return False
    query = url.split('?', 1)[1]
    if len(query) <= length_threshold:
        return False

    params = [p for p in query.split('&') if p]
    names = [p.split('=')[0].lower() for p in params if '=' in p]

    # 特征1：重复参数名（排除数组参数 name[] 模式）
    # name[]=v 重复是 PHP/Rails 等框架的标准数组传参语法，不是 HPP
    def _is_array_param(n):
        return n.endswith('[]') or n.endswith('%5b%5d')
    non_array_names = [n for n in names if not _is_array_param(n)]
    if len(non_array_names) != len(set(non_array_names)):
        return True

    # 特征2：参数值中含编码注入
    # %26（编码的 &）→ 注入新参数，强信号
    # %3D（编码的 =）→ 仅在值内部中间位置才算注入；末尾 %3D 或 %3D%3D 是 Base64 padding
    for p in params:
        if '=' in p:
            val = p.split('=', 1)[1].lower()
            if '%26' in val:
                return True
            idx = val.find('%3d')
            while idx != -1:
                after = val[idx + 3:]
                # %3D 后面有实质性内容（非纯 %3D 连续 padding）→ 编码注入
                if after and not re.match(r'^(%3d)*$', after):
                    return True
                idx = val.find('%3d', idx + 3)

    # 特征3：参数数量异常多（≥15 个不同参数）
    if len(set(names)) >= 15:
        return True

    return False


def has_garbled_url(url: str) -> bool:
    """URL 中出现大量非打印字符或高字节则认为乱码。
    排除中文字符（CJK Unicode 范围 U+4E00–U+9FFF 及扩展区）：
    中文资源名是正常业务，不属于 Abnormal URL。
    """
    if not url:
        return False
    # URL 编码后的中文（%E4%B8%AD 等）不含高字节，不触发计数
    # 但如果 URL 已解码，需排除 CJK 字符
    def is_cjk(c):
        cp = ord(c)
        return (0x4E00 <= cp <= 0x9FFF or   # CJK Unified Ideographs
                0x3400 <= cp <= 0x4DBF or   # Extension A
                0x20000 <= cp <= 0x2A6DF or # Extension B
                0xF900 <= cp <= 0xFAFF or   # CJK Compatibility
                0xFF00 <= cp <= 0xFFEF)      # Halfwidth/Fullwidth
    non_print = sum(1 for c in url
                    if not is_cjk(c) and
                    (ord(c) > 127 or (ord(c) < 32 and ord(c) not in (9, 10, 13))))
    return non_print > _c('abnormal_url','garbled_non_print_min') or (len(url) > 0 and non_print / len(url) > _c('abnormal_url','garbled_non_print_ratio'))


def is_abnormal_ua(ua: str) -> bool:
    """UA 异常判定：
    - UA 缺失（空）：不算 Abnormal UA，正常攻击工具/脚本可能不带 UA
    - UA 包含已知攻击工具关键字（masscan/nmap/curl/wget 等）：Abnormal
    - UA 存在但不含任何浏览器/标准客户端标识：Abnormal
    """
    if not ua:
        return False   # 缺少 UA ≠ Abnormal UA
    ua_l = ua.lower()
    if any(t in ua_l for t in TOOL_UA_PATTERNS):
        return True
    # 格式非标准：缺少 Mozilla/ 或 任何浏览器标识
    if not any(k in ua_l for k in ('mozilla/', 'opera/', 'curl/', 'wget/',
                                    'python', 'go-http', 'java/', 'okhttp')):
        return True
    return False


def has_tls_client_hello(payload: bytes) -> bool:
    return (len(payload) >= 6 and payload[0] == 0x16
            and payload[1] == 0x03 and payload[5] == 0x01)


def has_tls_change_cipher(payload: bytes) -> bool:
    return len(payload) >= 3 and payload[0] == 0x14 and payload[1] == 0x03


def has_tls_app_data(payload: bytes) -> bool:
    return len(payload) >= 3 and payload[0] == 0x17 and payload[1] == 0x03


def extract_sni(payload: bytes) -> str:
    """从 TLS ClientHello 中提取 SNI"""
    try:
        if not has_tls_client_hello(payload):
            return ''
        # TLS record header: 5 bytes, Handshake header: 4 bytes
        # ClientHello: 2(ver) + 32(random) + 1(sess_len) + sess + 2(cipher_len) + ...
        pos = 9  # skip record(5) + handshake type(1) + length(3)
        pos += 2 + 32  # client version + random
        sess_len = payload[pos]; pos += 1 + sess_len
        cipher_len = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2 + cipher_len
        comp_len = payload[pos]; pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ''
        ext_total = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = struct.unpack('>H', payload[pos:pos+2])[0]
            ext_len  = struct.unpack('>H', payload[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0:  # SNI
                # list_len(2) + type(1) + name_len(2) + name
                if pos + 5 <= len(payload):
                    name_len = struct.unpack('>H', payload[pos+3:pos+5])[0]
                    return payload[pos+5:pos+5+name_len].decode('ascii', 'replace')
            pos += ext_len
    except Exception:
        pass
    return ''


def extract_alpn(payload: bytes) -> list:
    """从 TLS ClientHello 中提取 ALPN Protocol 列表，返回如 ['h2', 'http/1.1']"""
    try:
        if not has_tls_client_hello(payload):
            return []
        pos = 9
        pos += 2 + 32                                                   # client version + random
        sess_len = payload[pos]; pos += 1 + sess_len                    # session id
        cipher_len = struct.unpack('>H', payload[pos:pos+2])[0]
        pos += 2 + cipher_len                                           # cipher suites
        comp_len = payload[pos]; pos += 1 + comp_len                    # compression methods
        if pos + 2 > len(payload):
            return []
        ext_total = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = struct.unpack('>H', payload[pos:pos+2])[0]
            ext_len  = struct.unpack('>H', payload[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0x0010:  # ALPN extension
                # ALPN: protocol_list_len(2) + [proto_len(1) + proto_name]*
                if pos + 2 <= len(payload):
                    list_len = struct.unpack('>H', payload[pos:pos+2])[0]
                    p2 = pos + 2
                    end2 = p2 + list_len
                    protocols = []
                    while p2 + 1 <= end2 and p2 + 1 <= len(payload):
                        plen = payload[p2]; p2 += 1
                        if plen == 0 or p2 + plen > len(payload):
                            break
                        protocols.append(payload[p2:p2+plen].decode('ascii', 'replace'))
                        p2 += plen
                    return protocols
            pos += ext_len
    except Exception:
        pass
    return []


def is_plaintext_http(payload: bytes) -> bool:
    for m in HTTP_METHODS:
        if payload[:len(m)] == m:
            after = len(m)
            if after < len(payload) and payload[after:after+1] in (b' ', b'\t'):
                return True
    return False


# =============================================================================
# JA4 TLS 客户端指纹（FoxIO JA4 规范）
# 参考：https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
# 格式：t<ver><sni_flag><cipher_cnt><ext_cnt><alpn>_<ciphers_sha>_<exts_sigalgos_sha>
# 示例：t13d1715h2_a09f3c656075_14788d8d241b
# =============================================================================

GREASE_VALUES = frozenset([
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
])

_TLS_VER_MAP = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3'}


def compute_ja4(payload: bytes, transport: str = 't') -> str:
    """
    从重组后的客户端 TLS 流量中解析 ClientHello，计算 JA4 指纹。

    Args:
        payload  : 至少包含完整 ClientHello 的重组字节流（带 record header）
        transport: 't'=TCP/TLS（默认）/ 'q'=QUIC / 'd'=DTLS

    Returns:
        JA4 字符串（如 't13d1715h2_a09f3c656075_14788d8d241b'），
        失败/非 ClientHello 返回 ''
    """
    import hashlib
    try:
        if not has_tls_client_hello(payload):
            return ''
        pos = 9                                       # 跳过 record(5)+handshake type(1)+len(3)
        legacy_ver = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        pos += 32                                     # random
        sess_len = payload[pos]; pos += 1 + sess_len  # session id

        # cipher suites（去 GREASE）
        cipher_len = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            if pos + i + 2 > len(payload): break
            c = struct.unpack('>H', payload[pos+i:pos+i+2])[0]
            if c not in GREASE_VALUES:
                ciphers.append(c)
        pos += cipher_len

        # compression methods
        comp_len = payload[pos]; pos += 1 + comp_len

        # extensions
        if pos + 2 > len(payload): return ''
        ext_total = struct.unpack('>H', payload[pos:pos+2])[0]; pos += 2
        ext_end   = pos + ext_total

        extensions          = []   # 全部非 GREASE 扩展类型（用于计数）
        sni_present         = False
        alpn_first          = ''
        sig_algos           = []   # 原始顺序（不排序）
        supported_versions  = []   # 客户端 supported_versions

        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = struct.unpack('>H', payload[pos:pos+2])[0]
            ext_len  = struct.unpack('>H', payload[pos+2:pos+4])[0]
            pos += 4
            ext_data = payload[pos:pos+ext_len]

            if ext_type not in GREASE_VALUES:
                extensions.append(ext_type)

            if ext_type == 0x0000:    # SNI
                sni_present = True
            elif ext_type == 0x0010:  # ALPN
                if len(ext_data) >= 3:
                    p_len = ext_data[2]
                    if 0 < p_len and 3 + p_len <= len(ext_data):
                        try:
                            alpn_first = ext_data[3:3+p_len].decode('ascii', 'replace')
                        except Exception:
                            alpn_first = ''
            elif ext_type == 0x000d:  # signature_algorithms（保序）
                if len(ext_data) >= 2:
                    sa_len = struct.unpack('>H', ext_data[:2])[0]
                    for i in range(0, sa_len, 2):
                        if 2 + i + 2 > len(ext_data): break
                        sig_algos.append(struct.unpack('>H', ext_data[2+i:2+i+2])[0])
            elif ext_type == 0x002b:  # supported_versions
                if len(ext_data) >= 1:
                    vlist_len = ext_data[0]
                    for i in range(0, vlist_len, 2):
                        if 1 + i + 2 > len(ext_data): break
                        v = struct.unpack('>H', ext_data[1+i:1+i+2])[0]
                        if v not in GREASE_VALUES:
                            supported_versions.append(v)
            pos += ext_len

        # 版本：取 supported_versions 最高，否则 legacy
        ver_word = max(supported_versions) if supported_versions else legacy_ver
        ver_str  = _TLS_VER_MAP.get(ver_word, '00')

        sni_flag = 'd' if sni_present else 'i'
        cc = min(len(ciphers), 99)
        ec = min(len(extensions), 99)

        # ALPN 首尾字符（不可打印或缺失 → "00"）
        if alpn_first and all(0x20 < ord(c) < 0x7F for c in alpn_first):
            alpn_str = alpn_first[0] + alpn_first[-1]
        else:
            alpn_str = '00'

        ja4_a = f'{transport}{ver_str}{sni_flag}{cc:02d}{ec:02d}{alpn_str}'

        # JA4_b: ciphers 字典序 → SHA256 前12位
        ja4_b_raw = ','.join(sorted(f'{c:04x}' for c in ciphers))
        ja4_b     = hashlib.sha256(ja4_b_raw.encode()).hexdigest()[:12]

        # JA4_c: extensions 字典序（剔除 SNI/ALPN）_ sig_algos 保序 → SHA256 前12位
        ext_sorted = sorted(f'{e:04x}' for e in extensions if e not in (0x0000, 0x0010))
        sa_str     = ','.join(f'{s:04x}' for s in sig_algos)
        ja4_c_raw  = ','.join(ext_sorted) + ('_' + sa_str if sa_str else '')
        ja4_c      = hashlib.sha256(ja4_c_raw.encode()).hexdigest()[:12]

        return f'{ja4_a}_{ja4_b}_{ja4_c}'
    except Exception:
        return ''


def load_ja4_blacklist(path: str) -> set:
    """
    加载 JA4 黑名单，支持两种 JSON 格式：

    1. 数组格式：
        ["t13d1715h2_a09f3c656075_14788d8d241b", "t13d1714h2_*"]

    2. 对象格式（推荐，可带说明字段）：
        {
          "_description": "...",
          "patterns": ["t13d1715h2_a09f3c656075_14788d8d241b", ...]
        }

    支持 fnmatch 通配符 *（前缀/后缀/中段匹配）。
    自动过滤明显非 JA4 格式的项（不以 t/q/d 开头）。
    """
    import json, os, re
    bl = set()
    if not path or not os.path.exists(path):
        return bl
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            items = data.get('patterns', [])
        elif isinstance(data, list):
            items = data
        else:
            items = []
        # JA4 形式校验：以 t/q/d 开头 + 至少含一个 '_'，或本身是带 * 的通配
        ja4_re = re.compile(r'^[tqd*][\w*]*_[\w*]*_[\w*]*$|^\*$')
        for item in items:
            if not isinstance(item, str): continue
            s = item.strip()
            if not s: continue
            if ja4_re.match(s):
                bl.add(s)
    except Exception as e:
        print(f'[WARN] JA4 黑名单加载失败 {path}: {e}')
    return bl


def match_ja4_blacklist(ja4: str, blacklist: set) -> str:
    """
    匹配 JA4 黑名单，返回命中的黑名单项（用于归类标识），未命中返回 ''。
    支持完整匹配与 * 通配。
    """
    if not ja4 or not blacklist:
        return ''
    if ja4 in blacklist:
        return ja4
    import fnmatch
    for pattern in blacklist:
        if '*' in pattern and fnmatch.fnmatchcase(ja4, pattern):
            return pattern
    return ''


# =============================================================================
# DNS 解析
# =============================================================================

def parse_dns(payload: bytes):
    """严格 DNS 解析，校验 label 格式和 qclass，降低垃圾包误判"""
    try:
        if len(payload) < 12:
            return None
        flags  = struct.unpack('>H', payload[2:4])[0]
        qr     = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        if opcode > 5:
            return None
        qdcnt = struct.unpack('>H', payload[4:6])[0]
        if qdcnt == 0 or qdcnt > 5:
            return None
        pos   = 12
        questions = []
        for _ in range(min(qdcnt, 5)):
            name_parts = []
            labels = 0
            while pos < len(payload):
                length = payload[pos]; pos += 1
                if length == 0:
                    break
                if length & 0xC0 == 0xC0:
                    pos += 1; break
                if length > 63:
                    return None
                labels += 1
                if labels > 10:
                    return None
                try:
                    label = payload[pos:pos+length].decode('ascii', 'strict')
                    if not all(c.isalnum() or c in '-_*' for c in label):
                        return None
                except (UnicodeDecodeError, ValueError):
                    return None
                name_parts.append(label)
                pos += length
            if pos + 4 > len(payload):
                break
            qtype  = struct.unpack('>H', payload[pos:pos+2])[0]
            qclass = struct.unpack('>H', payload[pos+2:pos+4])[0]
            pos += 4
            if qclass not in (1, 255):
                return None
            questions.append({'name': '.'.join(name_parts), 'qtype': qtype})
        if not questions:
            return None
        return {'qr': qr, 'is_response': qr == 1, 'questions': questions}
    except Exception:
        return None


# =============================================================================
# SIP 解析
# =============================================================================

def is_sip(payload: bytes) -> bool:
    """严格 SIP 识别：
    - 响应：payload 以 SIP/2.0 开头
    - 请求：方法名开头 + 后跟空格 + 包含 sip:/sips:/tel: URI 或 SIP/2.0 版本字符串
    （排除 HTTP OPTIONS 等以相同方法名开头的非 SIP 协议）
    SIP 支持任意端口，不限于 5060/5061
    """
    if payload[:7] == b'SIP/2.0':
        return True
    SIP_METHODS = [b'INVITE', b'REGISTER', b'OPTIONS', b'ACK',
                   b'BYE', b'CANCEL', b'UPDATE', b'REFER',
                   b'SUBSCRIBE', b'NOTIFY', b'INFO', b'PRACK']
    for m in SIP_METHODS:
        if payload[:len(m)] == m:
            # 方法后必须跟空格，且 payload 前 50 字节含 SIP URI 或版本字符串
            after = payload[len(m):len(m)+1]
            if after == b' ':
                head = payload[:50]
                if (b'sip:' in head or b'sips:' in head or
                        b'tel:' in head or b'SIP/2.0' in head):
                    return True
    return False


def _is_sip_response(payload: bytes) -> bool:
    """SIP 反射响应识别：仅接受 SIP/2.0 开头的响应报文（200 OK / 180 Ringing / 486 Busy 等）。
    SIP request（INVITE/OPTIONS/REGISTER 等）不属于反射响应，不计入。
    用于 UDP 反射分类器中区分 SIP 反射响应与 SIP 请求报文。
    """
    return payload[:7] == b'SIP/2.0'


def _is_valid_dns_response(pl: bytes) -> bool:
    """DNS response：QR=1，长度>=12，OPCODE合法(0-5)
    包括 NXDOMAIN/SERVFAIL 等错误响应（ANCOUNT=0也是合法反射响应）
    RCODE: 0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED
    """
    if len(pl) < 12: return False
    flags   = struct.unpack('>H', pl[2:4])[0]
    qr      = (flags >> 15) & 1
    opcode  = (flags >> 11) & 0xF
    rcode   = flags & 0xF
    if qr != 1: return False
    if opcode > 5: return False          # 非法 opcode
    # NOERROR/NXDOMAIN/SERVFAIL/REFUSED 都是合法反射响应
    # 仅排除保留错误码（6-15中的非标准值）
    if rcode > 5 and rcode not in (6, 7, 8, 9, 10): return True  # 宽松放行
    return True  # QR=1 + 合法 opcode 即认为是 DNS 响应

def _is_valid_ntp(pl: bytes) -> bool:
    """NTP 反射响应：仅识别 MON_GETLIST response（mode=7，R bit=1）。
    用户定义：NTP 反射 = response MON_GETLIST 报文，不包括标准 mode=4(server)/mode=5(broadcast)。
    mode=4/5 标准响应（含伪造 NTP 头的 UDP Flood）不归反射，落入 UDP Flood 分类。

    NTP mode=7 byte0 格式（ntpd RM_VN_MODE macro）：
      byte0 = (R<<7) | (M<<6) | (E<<3) | (VN<<3) | mode
      即：R bit 在 pl[0] 的 bit7，不在 pl[1]。
    常见值：0x17 = Request(R=0, VN=2, mode=7)
            0x97 = Response(R=1, M=0, VN=2, mode=7)
            0xd7 = Response+More(R=1, M=1, VN=2, mode=7)
    """
    if len(pl) < 8: return False
    mode = pl[0] & 0x7
    if mode != 7: return False      # 严格限定 mode=7（Private/MON_GETLIST）
    r_bit = (pl[0] >> 7) & 1       # R bit 在 pl[0] bit7，不是 pl[1]
    return r_bit == 1               # R=1：response

def _is_valid_snmp(pl: bytes) -> bool:
    """SNMP 反射响应：文档要求 GetResponse 且包含大量 OID 数据
    PDU type 收紧：
      0xa2 = GetResponse（主要反射响应类型）
      0xa7 = InformRequest（v2c trap，服务端主动发出）
      0xa8 = SNMPv2-Trap（trap 响应）
    排除请求类型：0xa0(GetRequest)、0xa1(GetNextRequest)、0xa3(SetRequest)、0xa5(GetBulkRequest)
    SNMP 为 ASN.1/BER 编码，不含 ASCII 字符串 'SNMP'，
    依赖协议结构识别比字符串特征更准确。
    """
    if len(pl) < 8: return False
    if pl[0] == 0x30:
        for i in range(2, min(64, len(pl))):
            if pl[i] in (0xa2, 0xa7, 0xa8):   # GetResponse / InformRequest / SNMPv2-Trap
                return True
    pl_lower = pl[:128].lower()
    return (b'public' in pl_lower or
            b'private' in pl_lower or
            b'\x00public' in pl or
            b'\x00private' in pl)

def _is_valid_ssdp(pl: bytes) -> bool:
    """SSDP 反射响应：HTTP/1.1 200 OK 或 NOTIFY，且含 UPnP/SSDP 专属关键字（原则3/4）
    注：M-SEARCH 是请求报文（诱发报文），不是反射响应，由 _is_amp_ssdp 识别
    """
    pl_lower = pl[:256].lower()
    # SSDP 反射响应：HTTP 200 OK 或 NOTIFY
    is_response_type = (pl[:15] == b'HTTP/1.1 200 OK' or pl[:6] == b'NOTIFY')
    if not is_response_type:
        return False
    # 必须含 UPnP/SSDP 专属字段
    return (b'upnp/' in pl_lower or
            b'upnp' in pl_lower or
            b'ssdp:' in pl_lower or
            b'usn:' in pl_lower or
            b'nts:' in pl_lower or
            b'\r\ncache-control:' in pl_lower or
            b'\r\nlocation: http' in pl_lower)

def _is_valid_memcached(pl: bytes) -> bool:
    """Memcached 反射响应（文本协议 + 严格二进制协议双路径）。

    Memcached over UDP 格式：8字节 UDP framing header + 协议体
      UDP framing: request_id(2) + seq_no(2) + total_datagrams(2) + reserved(2)

    文本协议响应（用户定义）：
      body 以 VALUE 或 END 开头
      VALUE 格式：VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n
      END   格式：END\r\n（空响应）

    二进制协议响应（严格校验）：
      body[0] = 0x81（response magic）
      body[1] = opcode，合法范围 0x00-0x25（Get/Set/Delete/Increment 等）
      body 长度 >= 24（binary protocol header 固定 24 字节）
      不接受 opcode 超出合法范围的包（随机 payload 误匹配风险极高）
    """
    if len(pl) < 8:
        return False

    # 跳过 8 字节 UDP framing header，取协议体
    body = pl[8:]

    # 文本协议响应：VALUE 或 END 开头
    if body[:5] == b'VALUE' or body[:3] == b'END':
        return True

    # 文本协议其他响应关键字
    if len(body) >= 6:
        if body[:6] in (b'STORED', b'EXISTS'):
            return True
    if len(body) >= 7 and body[:7] in (b'DELETED', b'TOUCHED'):
        return True
    if len(body) >= 9 and body[:9] == b'NOT_FOUND':
        return True
    if b'CLIENT_ERROR' in body[:32] or b'SERVER_ERROR' in body[:32]:
        return True

    # 二进制协议响应：magic=0x81 + Get 类 opcode + 足够长度
    # 攻击者用 get/gets 诱发，服务端响应 opcode 对应 Get 类：
    #   0x00=Get  0x09=GetQ  0x0c=GetK  0x0d=GetKQ
    # 不接受 Delete/SASL/Stat 等无关 opcode（随机数据误匹配风险）
    MEMCACHED_GET_RESPONSE_OPCODES = {0x00, 0x09, 0x0c, 0x0d}
    if len(body) >= 24 and body[0] == 0x81:
        if body[1] in MEMCACHED_GET_RESPONSE_OPCODES:
            return True

    return False

def _is_valid_cldap(pl: bytes) -> bool:
    """CLDAP (Connectionless LDAP)：ASN.1 SEQUENCE(0x30) + 正确解析 BER 长度
    + messageID(INTEGER) + protocolOp。
    
    修复：正确跳过 BER 长度字段，从 protocolOp 位置识别 LDAP 操作码。
    
    LDAP APPLICATION tags（0x60-0x7f）：BindReq/Resp、SearchReq/Entry/Done 等
    CLDAP context-specific（0xa0-0xaf）：CLDAP 使用 context tags 封装 LDAP 操作，
      在 port=389 上这些是合法 LDAP/CLDAP 操作，不是 SNMP（SNMP 在 port=161）。
    原有逻辑错误：扫描前128字节遇到 0xa0-0xaf 就判定为 SNMP，
      实际上 CLDAP SearchResponse 的 protocolOp 本身就是 context tag。
    """
    if len(pl) < 8 or pl[0] != 0x30: return False

    # 解析 BER 长度，跳到 messageID
    pos = 1
    if pos >= len(pl): return False
    lb = pl[pos]; pos += 1
    if lb & 0x80:
        nb = lb & 0x7f  # 后几字节是长度
        if nb == 0 or nb > 4 or pos + nb > len(pl): return False
        pos += nb       # 跳过长度字节

    # messageID 必须是 INTEGER(0x02)
    if pos + 2 > len(pl): return False
    if pl[pos] != 0x02: return False
    mid_len = pl[pos + 1]
    if pos + 2 + mid_len >= len(pl): return False
    pos += 2 + mid_len

    # protocolOp
    proto_op = pl[pos]
    # LDAP APPLICATION class (0x60-0x7f)：BindReq/Resp, SearchReq/Entry/Done...
    if 0x60 <= proto_op <= 0x7f: return True
    # CLDAP context-specific (0xa0-0xaf)：CLDAP 合法操作，port=389 上不是 SNMP
    if 0xa0 <= proto_op <= 0xaf: return True
    # 大包（>200B）且结构符合前两步 → 宽松识别
    if len(pl) > 200: return True
    # 字符串特征（原则4）：CLDAP 反射响应含 NamingContext 或 ldap 关键字
    pl_lower = pl[:256].lower()
    if b'namingcontext' in pl_lower or b'ldap' in pl_lower:
        return True
    return False

def _is_valid_chargen(pl: bytes) -> bool:
    """Chargen：payload 为可打印 ASCII 字符"""
    if len(pl) < 4: return False
    return all(0x20 <= b < 0x7f or b in (0x0d, 0x0a) for b in pl[:32])

def _is_valid_mdns(pl: bytes) -> bool:
    """mDNS 反射响应：DNS 格式且 QR=1（响应），且 qdcount 合理（≤10）。
    排除随机 payload 恰好使 QR bit 置位的情况（qdcount 异常大是明显特征）。
    """
    if len(pl) < 12: return False
    flags16 = (pl[2] << 8) | pl[3]
    qr      = (flags16 >> 15) & 1
    opcode  = (flags16 >> 11) & 0xF
    qdcount = (pl[4] << 8) | pl[5]
    ancount = (pl[6] << 8) | pl[7]
    if qr != 1: return False
    if opcode > 5: return False
    if qdcount > _c('dns','mdns_qdcount_max'): return False         # 真实 DNS 查询数量极少超过 10
    if ancount == 0 and qdcount == 0: return False
    return True

def _is_valid_coap(pl: bytes) -> bool:
    """CoAP 反射响应：version=1，Type=ACK(2)/RST(3)，code合法，
    或含 'title=' 字符串特征（原则4），表示 CoAP well-known/core 响应内容
    """
    if len(pl) < 4: return False
    ver  = (pl[0] >> 6) & 0x3
    typ  = (pl[0] >> 4) & 0x3
    code = pl[1]
    if ver != 1: return False
    # 反射响应通常是 ACK(2)/RST(3)，也接受 CON(0)/NON(1)
    if 0x20 <= code < 0x40: return False
    # 字符串特征：CoAP well-known 响应（原则4）
    if b'title=' in pl:
        return True
    return True

def _is_valid_bittorrent(pl: bytes) -> bool:
    """BitTorrent DHT 反射响应：合法 bencode 字典且为响应包（y=r）。
    DHT 反射攻击：攻击者伪造受害者 IP 发 get_peers 查询（y=q）到大量 DHT 节点，
    节点将 get_peers 响应（y=r，含 values/nodes）回发给受害者。
    反射报文特征：
      - bencode 字典格式（d 开头，e 结尾）
      - 包含 1:y1:r（DHT 响应类型标志）
      - 通常含 values（peers 列表）或 nodes（最近节点）
    排除查询包（y=q）：get_peers/find_node/sample_infohash 等查询是诱发报文，不是反射响应
    """
    if len(pl) < 10: return False
    if pl[0] != ord('d'): return False
    if len(pl) > 512: return False
    if pl[-1] != ord('e'): return False
    # 必须是 DHT 响应（y=r），查询（y=q）不归反射
    return b'1:y1:r' in pl

def _is_valid_stun(pl: bytes) -> bool:
    """STUN 反射响应：Magic Cookie=0x2112A442，且 msg_type 为 Success/Error Response。
    STUN msg_type 编码：C1(bit8)=1 表示响应类（Success Response 或 Error Response）。
    Binding Request(0x0001) C1=0 被排除，避免误归诱发报文为反射响应。
    """
    if len(pl) < 20: return False
    if pl[0] & 0xC0 != 0: return False
    magic = struct.unpack('>I', pl[4:8])[0]
    if magic != 0x2112A442: return False
    msg_type = struct.unpack('>H', pl[0:2])[0] & 0x3FFF
    return bool(msg_type & 0x0100)   # C1 bit=1: Success/Error Response

def _is_valid_quake(pl: bytes) -> bool:
    """Quake/Q3/Source Engine：以 0xFF 0xFF 0xFF 0xFF 开头"""
    return len(pl) >= 4 and pl[:4] == b'\xff\xff\xff\xff'

def _is_valid_steam(pl: bytes) -> bool:
    """Steam / Source Engine 同 Quake"""
    return _is_valid_quake(pl)

def _is_valid_portmap(pl: bytes) -> bool:
    """Portmap/RPC：最小28字节，reply(1)"""
    if len(pl) < 28: return False
    msg_type = struct.unpack('>I', pl[4:8])[0]  # 1=REPLY
    return msg_type == 1

def _is_valid_rdp(pl: bytes) -> bool:
    """RDP over TCP：TPKT header 03 00"""
    return len(pl) >= 4 and pl[0] == 0x03 and pl[1] == 0x00

def _is_valid_rdpudp(pl: bytes) -> bool:
    """RDP over UDP (MS-RDPEUDP)：uFlags字段含SYN(0x0001)或ACK(0x0100)标志
    RDPUDP FEC Header：snSourceAck(2) + uReceiveWindowSize(2) + uFlags(2)"""
    if len(pl) < 6: return False
    u_flags = struct.unpack('>H', pl[4:6])[0]
    # 合法flags：SYN=0x0001, ACK=0x0100, SYN+ACK=0x0101, FEC=0x0008等
    return (u_flags & 0x0001) or (u_flags & 0x0100) or (u_flags & 0x0008)

def _is_valid_wsd(pl: bytes) -> bool:
    """WSD/WS-Discovery 反射响应：ProbeMatch（含详细设备描述的XML）
    文档 fingerprint 表要求：ProbeMatch, Types, Scopes
    ProbeMatch 是 WS-Discovery 发现响应的标准消息类型，区别于 Probe（探测请求）
    原则4：soap-envelope / discovery 字符串特征
    """
    pl_lower = pl[:256].lower()
    # 优先匹配 ProbeMatch（最强特征，文档明确要求）
    if b'probematch' in pl_lower:
        return True
    # Types 和 Scopes 是 ProbeMatch 响应中的标准字段
    if b'types' in pl_lower and b'scopes' in pl_lower:
        return True
    # 通用 XML/SOAP 特征（兜底）
    return (pl[:5] == b'<?xml'
            or b'<soap' in pl_lower
            or b'<s:en' in pl_lower
            or b'soap-envelope' in pl_lower
            or b'discovery' in pl_lower
            or b'onvif' in pl_lower
            or b'ws-discovery' in pl_lower
            or b'wsdiscovery' in pl_lower)

def _is_valid_plex(pl: bytes) -> bool:
    """Plex：固定8字节头 PLEX ..."""
    return len(pl) >= 8 and pl[:4] == b'PLEX'

def _is_valid_ubiquiti(pl: bytes) -> bool:
    """Ubiquiti Discovery Protocol 反射响应（仅用于 sport=10001 固定端口场景）：
    协议格式：byte0=0x01(version)，byte1=0x00(command/response)，
              byte2-3=TLV总长度(big-endian)，bytes4+为TLV数据。
    Response（反射）：TLV length 在合理范围（10~600），实测约 147-172 字节。
    Request probe（诱发）：\x01\x00\x00\x00 或 \x02\x08\x00\x00（TLV length=0，无TLV）。
    Ubiquiti 响应固定从 sport=10001 发出，不存在随机 sport 场景。
    """
    if len(pl) < 4: return False
    if pl[0] == 0x01 and pl[1] == 0x00:
        pkt_len = struct.unpack('>H', pl[2:4])[0]
        # TLV length 合理范围：排除探测包（length=0）和随机数据碰撞（超大值）
        # 实测正常响应约 147-172 字节，边界包最大约 1414；随机数据碰撞值通常 > 10000
        if 10 <= pkt_len <= 1500:
            return True
    return False

def _is_valid_ike(pl: bytes) -> bool:
    """IKE 反射响应（UDP 500）：IKE header >= 28 字节。
    IKE header layout: [0:8]=SPI_i, [8:16]=SPI_r, [16]=NextPayload,
    [17]=Version, [18]=ExchangeType, [19]=Flags, [20:24]=MsgID, [24:28]=Length
    IKEv2（ver高nibble=0x20）：Flags R bit(0x20)=1 表示响应包。
    IKEv1（ver高nibble=0x10）：Responder SPI([8:16])非全零表示响应（初始请求 spi_r 全零）。
    """
    if len(pl) < 28: return False
    version = pl[17]
    if version & 0xF0 == 0x20:     # IKEv2（major=2）
        return bool(pl[19] & 0x20) # Flags R bit=1: Response
    if version & 0xF0 == 0x10:     # IKEv1（major=1）：Responder SPI 非零 = 响应包
        return pl[8:16] != b'\x00\x00\x00\x00\x00\x00\x00\x00'
    return False


def _is_valid_ike_nat(pl: bytes) -> bool:
    """IKE-NAT 反射响应（UDP 4500）：
    UDP 4500 载荷分两种格式：
    1. IKE 控制报文：前 4 字节为 Non-ESP Marker (0x00000000)，之后接标准 IKE header（偏移 4）。
    2. ESP 数据报文：前 4 字节为非零 SPI（SN 4B + IV + 密文），也属于 IKE-NAT 反射范畴。
    识别原则（原则文档）：
      前 4 字节全零 → IKE 协商报文，核验 IKE header（偏移 4）的版本/R bit/spi_r。
      前 4 字节非零 → ESP 加密报文，payload >= 8B（SPI 4B + SN 4B）即视为合法反射包。
    """
    if len(pl) < 8: return False
    if pl[0:4] == b'\x00\x00\x00\x00':
        # IKE 控制报文：Non-ESP Marker + IKE header（从 offset 4 开始）
        return _is_valid_ike(pl[4:])
    # ESP 数据报文：前 4 字节为非零 SPI，已通过最小长度检查
    return True

def _is_valid_ripv1(pl: bytes) -> bool:
    """RIPv1 response：cmd=2, version=1"""
    return len(pl) >= 4 and pl[0] == 2 and pl[1] == 1

def _is_valid_kerberos(pl: bytes) -> bool:
    """Kerberos 反射响应：ASN.1 APPLICATION tag 为 KDC 响应类型。
    仅接受 KDC 发出的响应消息：
      0x6b = AS-REP  (Application 11, KDC 响应 AS-REQ)
      0x6d = TGS-REP (Application 13, KDC 响应 TGS-REQ)
      0x6f = AP-REP  (Application 15, 应用服务器响应 AP-REQ)
      0x7e = KRB-ERROR (Application 30, KDC 错误响应)
    排除请求类型：0x6a=AS-REQ, 0x6c=TGS-REQ, 0x6e=AP-REQ（原代码误含 0x6c/0x6e）
    """
    return len(pl) >= 8 and pl[0] in (0x6b, 0x6d, 0x6f, 0x7e)

def _is_valid_openvpn(pl: bytes) -> bool:
    """OpenVPN：Packet Opcode 在合法范围"""
    if len(pl) < 2: return False
    opcode = pl[0] >> 3
    return 1 <= opcode <= 10

def _is_valid_bacnet(pl: bytes) -> bool:
    """BACnet BVLC：type=0x81"""
    return len(pl) >= 4 and pl[0] == 0x81

def _is_valid_l2tp(pl: bytes) -> bool:
    """L2TP 反射诱发报文：必须是控制包（T bit=1，flags 首字节最高位=1）
    且 Version=2（flags 低4位=0x2）或 Version=3（低4位=0x3）。
    T=0 是数据包，不能触发服务端响应，不是诱发报文。
    合法诱发类型：SCCRQ(tunnel建立)、ICRQ(session建立)、HELLO(保活)
    """
    if len(pl) < 8: return False
    flags16 = (pl[0] << 8) | pl[1]
    t_bit = (flags16 >> 15) & 1   # T=1: control, T=0: data
    ver   = pl[1] & 0xF
    return t_bit == 1 and ver in (2, 3)

def _is_valid_capwap(pl: bytes) -> bool:
    """CAPWAP：Preamble Version=0，首字节高4位=0"""
    return len(pl) >= 8 and (pl[0] >> 4) == 0

def _is_valid_dtls_record(pl: bytes) -> bool:
    """DTLS record 反射响应：服务端发出的 Handshake 消息。
    DTLS record 格式：content_type(1) + version(2,0xFExx) + epoch(2) + seq(6) + length(2) + fragment
    content_type：20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData
    反射报文（服务端发出）：
      content_type=22（Handshake）+ handshake_type ∈ {2=ServerHello, 11=Certificate,
      12=ServerKeyExchange, 13=CertificateRequest, 14=ServerHelloDone, 3=HelloVerifyRequest}
    排除 ClientHello（handshake_type=1）：方向是客户端→服务端，是诱发报文
    对于 sport=443（QUIC/DTLS 混用端口）：QUIC 路径已在 classify_udp_reflection 中优先处理，
    到达此 validator 的 sport=443 包是 DTLS record，直接校验格式。
    """
    if len(pl) < 13: return False
    content_type = pl[0]
    if content_type not in (20, 21, 22, 23): return False
    if pl[1] != 0xFE: return False  # DTLS version 高字节必须是 0xFE
    # Handshake 类型（content_type=22）：进一步检查 handshake_type 排除 ClientHello
    if content_type == 22 and len(pl) >= 14:
        handshake_type = pl[13]
        if handshake_type == 1: return False   # ClientHello：诱发报文，不是反射响应
    return True

def _is_valid_wireguard(pl: bytes) -> bool:
    """WireGuard 反射响应：消息类型为服务端发出的响应，首4字节小端 type，第2-4字节 reserved=0。
    Type 1(Initiation/148B) 是 client→server 的发起请求，不应出现在反射响应中，已排除。
    Type 2(Response/92B)  : server→client 握手响应 ✓
    Type 3(Cookie/64B)    : server→client cookie 响应 ✓
    Type 4(Transport/≥32B): 双向数据包，sport 为服务端端口时视为反射 ✓
    """
    if len(pl) < 32: return False
    msg_type = pl[0]
    reserved = pl[1:4]
    if reserved != b'\x00\x00\x00': return False
    if msg_type == 2: return len(pl) == 92    # Handshake Response
    if msg_type == 3: return len(pl) == 64    # Cookie Reply
    if msg_type == 4: return len(pl) >= 32    # Transport Data
    return False   # Type 1(Initiation) 是 client request，排除

def _is_valid_rtcp(pl: bytes) -> bool:
    """RTCP：Version=2(首字节高2位必须=10)，PT=200-211(SR/RR/SDES/BYE/APP等)
    ver=3的包（首字节高2位=11）是伪造的，严格排除。"""
    if len(pl) < 8: return False
    ver = (pl[0] >> 6) & 0x3
    pt  = pl[1]
    return ver == 2 and 200 <= pt <= 211


# =============================================================================
# UDP 反射诱发（Amplification Request）协议 Request 验证（原则2）
# 各协议独立 request validator，仅识别 request 报文，不接受 response。
# 不在 AMPLIFICATION_REQUEST_VALIDATORS 中的端口：不做诱发报文识别
# =============================================================================

def _is_amp_dns(pl: bytes) -> bool:
    """DNS 诱发：高放大倍数 qtype 查询（原则2）
    ANY(255)   – 多类型响应，历史最高放大比（多数服务器已封）
    DNSKEY(48) – DNSSEC 公钥记录，20–70× 放大，无需 DO bit
    DS(43)     – 委派签名记录，10–30×
    RRSIG(46)  – DNSSEC 签名记录，15–40×
    TXT(16)    – SPF/DMARC 等文本记录，10–50×
    AXFR(252)  – 区域传输，单次返回完整区域数据（可达 MB 级）
    IXFR(251)  – 增量区域传输
    """
    _AMP_QTYPES = {255, 48, 43, 46, 16, 252, 251}
    dns = parse_dns(pl)
    if dns is None or dns['is_response']:
        return False
    return any(q.get('qtype') in _AMP_QTYPES for q in dns['questions'])

def _is_amp_ntp(pl: bytes) -> bool:
    """NTP 诱发：MON_GETLIST request（mode=7，R bit=0，reqcode=42 或 20）（原则2）
    文档要求：Mode 7, ReqCode 42 (monlist)
    reqcode=20 = MON_GETLIST（旧版），reqcode=42 = MON_GETLIST_1（新版），均为 monlist 请求
    NTP mode=7 byte0 格式：R bit 在 pl[0] 的 bit7；reqcode 在 pl[3]
    """
    if len(pl) < 8: return False
    mode = pl[0] & 0x7
    if mode != 7: return False
    r_bit = (pl[0] >> 7) & 1
    if r_bit != 0: return False          # R=0: request
    reqcode = pl[3]
    return reqcode in (20, 42)           # 20=MON_GETLIST, 42=MON_GETLIST_1

def _is_amp_snmp(pl: bytes) -> bool:
    """SNMP 诱发：GetNextRequest(0xa1) 或 GetBulkRequest(0xa5)（原则2）
    文档要求：GetNextRequest 或 GetBulkRequest
    注：GetRequest(0xa0) 每次只取一个 OID，无放大效果，不属于诱发报文
    字符串特征：含 'public' community string（原则4）
    """
    if len(pl) < 8: return False
    if pl[0] == 0x30:
        for i in range(2, min(64, len(pl))):
            if pl[i] in (0xa1, 0xa5):   # GetNextRequest=0xa1, GetBulkRequest=0xa5
                return True
    pl_lower = pl[:128].lower()
    return b'public' in pl_lower

def _is_amp_stun(pl: bytes) -> bool:
    """STUN 诱发：Binding Request（msg type=0x0001）（原则2）"""
    if len(pl) < 20: return False
    if pl[0] & 0xC0 != 0: return False
    magic = struct.unpack('>I', pl[4:8])[0]
    if magic != 0x2112A442: return False
    msg_type = struct.unpack('>H', pl[0:2])[0] & 0x3FFF
    return msg_type == 0x0001   # Binding Request

def _is_amp_ssdp(pl: bytes) -> bool:
    """SSDP 诱发：M-SEARCH 请求，且含 upnp/ssdp 特征（原则2/4）"""
    if pl[:6] != b'M-SEAR': return False
    pl_lower = pl[:256].lower()
    return b'upnp' in pl_lower or b'ssdp:discover' in pl_lower

def _is_amp_cldap(pl: bytes) -> bool:
    """CLDAP 诱发：searchRequest（protocolOp=0x63），
    或字符串特征 'object class'（原则2/4）
    """
    if len(pl) < 8: return False
    # 字符串特征（原则4）
    pl_lower = pl[:256].lower()
    if b'object class' in pl_lower:
        return True
    if pl[0] != 0x30: return False
    pos = 1
    lb = pl[pos]; pos += 1
    if lb & 0x80:
        nb = lb & 0x7f
        if nb == 0 or nb > 4 or pos + nb > len(pl): return False
        pos += nb
    if pos + 2 > len(pl) or pl[pos] != 0x02: return False
    mid_len = pl[pos + 1]
    if pos + 2 + mid_len >= len(pl): return False
    pos += 2 + mid_len
    return pos < len(pl) and pl[pos] == 0x63   # searchRequest

def _is_amp_memcached(pl: bytes) -> bool:
    """Memcached 诱发：文本协议 get/gets 命令。
    Memcached over UDP 格式：8字节 UDP framing header + 协议体
    文本协议请求：body 以 get 或 gets 开头（原则2）
    二进制协议请求：magic=0x80 + Get(0x00)/GetK(0x0c)/GetKQ(0x0d) opcode
    """
    if len(pl) < 8: return False
    body = pl[8:]  # 跳过 UDP framing header

    # 文本协议 get/gets 命令
    if body[:4].lower() == b'get ' or body[:5].lower() == b'gets ':
        return True

    # 二进制协议 request：magic=0x80 + Get 类 opcode
    if len(body) >= 24 and body[0] == 0x80:
        if body[1] in (0x00, 0x0c, 0x0d):   # Get / GetK / GetKQ
            return True

    return False

def _is_amp_ubiquiti(pl: bytes) -> bool:
    """Ubiquiti 诱发：标准 4 字节探测包
    \\x01\\x00\\x00\\x00 或 \\x02\\x08\\x00\\x00（原则2/4）
    """
    return len(pl) == 4 and pl in (b'\x01\x00\x00\x00', b'\x02\x08\x00\x00')

def _is_amp_bacnet(pl: bytes) -> bool:
    """BACnet 诱发：Who-Is request（BVLC type=0x81，function=0x0b）（原则2）"""
    if len(pl) < 4: return False
    return pl[0] == 0x81 and pl[1] == 0x0b

def _is_amp_dtls(pl: bytes) -> bool:
    """DTLS 诱发：ClientHello（content_type=22, handshake_type=1）（原则2）
    DTLS record 格式：content_type(1) + version(2) + epoch(2) + seq(6) + length(2) + handshake_type(1)...
    ClientHello handshake_type=1，是攻击者发向 DTLS 服务器的触发报文。
    """
    if len(pl) < 14: return False
    if pl[0] != 22: return False          # content_type=22（Handshake）
    if pl[1] != 0xFE: return False        # DTLS version 高字节
    handshake_type = pl[13]
    return handshake_type == 1            # ClientHello


def _is_amp_wsd(pl: bytes) -> bool:
    """WSD/ONVIF 诱发：含 'Probe' 字符串的 WS-Discovery 探测包（原则2/4）"""
    return b'Probe' in pl[:256]

def _is_amp_coap(pl: bytes) -> bool:
    """CoAP 诱发：文档要求 GET 请求且包含 Observe 选项（原则2/4）
    CoAP Observe 选项号=6，用于订阅资源变化，攻击者用此触发服务器持续推送
    Observe 在 CoAP 选项中以 delta 编码：若首个选项就是 Observe(6)，
    则选项头字节高4位(delta)=6，低4位(len)=0或1
    简化判断：payload 中含 well-known/core、device 或 Observe 选项标记
    """
    if len(pl) < 4: return False
    ver = (pl[0] >> 6) & 0x3
    if ver != 1: return False
    code = pl[1]
    # code=1 是 GET 方法
    if code != 0x01: return False
    # Observe 选项（option number=6）：在 CoAP options 区查找
    # 简化：检查 well-known/core URI 或 payload 中含 observe 关键字
    if b'well-known/core' in pl or b'device' in pl[:128]:
        return True
    # Observe 选项在 Token 之后：Token 长度在 pl[0] 低4位
    tkl = pl[0] & 0xF
    opt_start = 4 + tkl
    if opt_start < len(pl):
        # 第一个选项字节：高4位=delta，低4位=len
        opt_delta = (pl[opt_start] >> 4) & 0xF
        if opt_delta == 6:   # Option number 6 = Observe
            return True
    return False

def _is_amp_sip(pl: bytes) -> bool:
    """SIP 诱发：仅限 INVITE / OPTIONS / REGISTER 方法（原则2，排除 ACK/BYE 等）"""
    for method in (b'INVITE ', b'OPTIONS ', b'REGISTER '):
        if pl[:len(method)] == method:
            head = pl[:50]
            if b'sip:' in head or b'sips:' in head or b'SIP/2.0' in head:
                return True
    return False

# 已知反射端口 -> 诱发报文（request）验证函数（原则2）
# 仅包含有明确 request 特征的协议；不在此字典中的端口不识别诱发报文
AMPLIFICATION_REQUEST_VALIDATORS: dict = {
    53:    _is_amp_dns,        # DNS ANY or TXT query
    123:   _is_amp_ntp,        # NTP MON_GETLIST request (mode=7, R=0)
    161:   _is_amp_snmp,       # SNMP GetBulk/Get request
    389:   _is_amp_cldap,      # CLDAP searchRequest
    1900:  _is_amp_ssdp,       # SSDP M-SEARCH
    11211: _is_amp_memcached,  # Memcached get/gets
    3478:  _is_amp_stun,       # STUN Binding Request
    3479:  _is_amp_stun,
    10001: _is_amp_ubiquiti,   # Ubiquiti 4-byte probe
    47808: _is_amp_bacnet,     # BACnet Who-Is
    3702:  _is_amp_wsd,        # WSD Probe
    5683:  _is_amp_coap,       # CoAP well-known/core
    5060:  _is_amp_sip,        # SIP INVITE/OPTIONS/REGISTER
    5061:  _is_amp_sip,
    4433:  _is_amp_dtls,       # DTLS ClientHello（标准端口）
    5684:  _is_amp_dtls,       # CoAP-over-DTLS ClientHello
}

# 已知反射端口 -> 对应的 RFC 验证函数（返回 True 表示是合法反射响应）
REFLECTION_VALIDATORS: dict = {
    53:    _is_valid_dns_response,   # DNS
    5353:  _is_valid_mdns,           # mDNS
    123:   _is_valid_ntp,            # NTP
    161:   _is_valid_snmp,           # SNMP
    1900:  _is_valid_ssdp,           # SSDP
    11211: _is_valid_memcached,      # Memcached
    389:   _is_valid_cldap,          # CLDAP
    19:    _is_valid_chargen,        # Chargen
    5683:  _is_valid_coap,           # CoAP
    6881:  _is_valid_bittorrent,     # BitTorrent DHT
    3478:  _is_valid_stun,           # STUN
    3479:  _is_valid_stun,
    27960: _is_valid_quake,          # Quake
    27015: _is_valid_steam,          # Steam
    111:   _is_valid_portmap,        # Portmap/RPC
    3702:  _is_valid_wsd,            # WSD/ONVIF
    32414: _is_valid_plex,           # Plex
    10001: _is_valid_ubiquiti,       # Ubiquiti
    500:   _is_valid_ike,            # IKE
    4500:  _is_valid_ike_nat,        # IKE-NAT（Non-ESP Marker + IKE / ESP）
    520:   _is_valid_ripv1,          # RIP
    88:    _is_valid_kerberos,       # Kerberos
    1194:  _is_valid_openvpn,        # OpenVPN
    47808: _is_valid_bacnet,         # BACnet
    1701:  _is_valid_l2tp,           # L2TP
    5246:  _is_valid_capwap,         # CAPWAP
    5247:  _is_valid_capwap,
    443:   _is_valid_dtls_record,    # QUIC/DTLS over UDP
    # DTLS 反射（sport=4433/5684）：
    #   4433 = 标准 DTLS 服务端端口（RFC 6347）
    #   5684 = CoAP-over-DTLS（RFC 7252）
    # 反射报文为服务端发出的 ServerHello/HelloVerifyRequest/ServerKeyExchange
    # 使用 _is_valid_dtls_record：content_type ∈ {20,21,22,23} + version=0xFE??
    # content_type 22=Handshake（ServerHello/Certificate 等服务端握手消息）
    # 客户端 ClientHello（content_type=22 + 方向靠 dport 区分）由 AMPLIFICATION_REQUEST_VALIDATORS 处理
    4433:  _is_valid_dtls_record,    # DTLS（标准端口）
    5684:  _is_valid_dtls_record,    # CoAP-over-DTLS
    5004:  _is_valid_rtcp,           # RTCP
    5005:  _is_valid_rtcp,
    51820: _is_valid_wireguard,      # WireGuard
    17500: lambda pl: len(pl) >= 4,  # Dropbox LAN sync
    137:   _is_valid_dns_response,   # NetBIOS-NS
    138:   lambda pl: len(pl) >= 10, # NetBIOS-DGM
    623:   lambda pl: len(pl) >= 10, # IPMI
    1434:  lambda pl: (
        len(pl) >= 32 and len(pl) <= 512 and            # 真实 MSSQL Browser 响应 < 512B
        pl[0] in (0x04, 0x05)                           # 0x04=PRELOGIN, 0x05=SVR_RESP
    ),  # MSSQL SVR_RESP/PRELOGIN
    2123:  lambda pl: len(pl) >= 8,  # GTPv1
    3283:  lambda pl: len(pl) >= 4,  # Apple Remote Desktop
    3386:  lambda pl: len(pl) >= 8,  # GTP
    4739:  lambda pl: len(pl) >= 16, # IPFIX
    5060:  lambda pl: pl[:7] == b'SIP/2.0',                          # SIP response only（200 OK/180/486 等）
    25565: lambda pl: (
        (len(pl) >= 7 and pl[0:2] == b'\xfe\xfd') or          # Query REQUEST 魔数（handshake/stat）
        (len(pl) >= 5 and pl[0] == 0x09) or                    # Query RESPONSE: handshake（含 challenge_token）
        (len(pl) >= 20 and pl[0] == 0x00)                      # Query RESPONSE: stat（含完整服务器信息，最少20字节）
    ),  # Minecraft Query
    30718: lambda pl: len(pl) >= 4,  # Lantronix
    9:     lambda pl: len(pl) == 0,  # Discard
    7:     lambda pl: True,          # Echo
    17:    lambda pl: len(pl) >= 4,  # QOTD
}

# ── UDP 反射危害等级分组（按高危→中危→低危顺序识别）────────────────────────────
# 用于 payload_matches_any_reflection 和 identify_proto_by_payload 的优先级排序
REFLECTION_HIGH_RISK_PORTS  = {389, 53, 5353, 123, 1900, 11211}        # CLDAP/DNS/NTP/SSDP/Memcached
REFLECTION_MID_RISK_PORTS   = {161, 3702, 19, 1194, 3478, 3479, 5683, 10001}  # SNMP/WSD/Chargen/OpenVPN/STUN/CoAP/Ubiquiti
# 低危：其余所有已知反射端口

def _ordered_reflection_validators():
    """按高危→中危→低危顺序返回 (port, validator) 列表"""
    high = [(p, v) for p, v in REFLECTION_VALIDATORS.items() if p in REFLECTION_HIGH_RISK_PORTS]
    mid  = [(p, v) for p, v in REFLECTION_VALIDATORS.items() if p in REFLECTION_MID_RISK_PORTS]
    low  = [(p, v) for p, v in REFLECTION_VALIDATORS.items()
            if p not in REFLECTION_HIGH_RISK_PORTS and p not in REFLECTION_MID_RISK_PORTS]
    return high + mid + low

ORDERED_REFLECTION_VALIDATORS = _ordered_reflection_validators()

# ── randomsport 允许列表 ──────────────────────────────────────────────────────
# 仅以下协议允许 sport 随机（运维实践确认会变端口）
# 其他协议必须 sport 固定在已知端口，否则不归反射
RANDOMSPORT_ALLOWED_PROTOS = {
    # 仅 WSD/SSDP/BitTorrent 考虑端口变化，依靠 payload 指纹识别
    # Ubiquiti：响应固定从 sport=10001 发出，不存在随机 sport 场景，不在此列
    # DNS/NTP/SNMP/Memcached/CLDAP/mDNS 等端口固定，用端口+指纹识别，不在此列
    'SSDP', 'WSD', 'BitTorrent',
}

# ── 变端口 payload 识别函数集（仅 WSD/SSDP/BitTorrent 3 个协议）────────────
# 这 3 个协议合法存在随机 sport 场景，依靠 payload 指纹唯一识别：
#   SSDP       - UPnP 响应从随机端口发出（HTTP/1.1 200 OK + UPnP 特征）
#   WSD        - WS-Discovery 响应从随机端口发出（ProbeMatch XML）
#   BitTorrent - DHT 节点响应从随机端口发出（bencode 'd' + DHT key）
# Ubiquiti：响应固定从 sport=10001 发出，由 REFLECTION_VALIDATORS[10001] 处理；
#   U7/M5/E300/UniFi 均为 2 字节字符串，在 256 字节随机 payload 中误命中率极高，
#   不适合作为随机 sport 的唯一识别依据。
# DNS/NTP/SNMP/Memcached/CLDAP/mDNS/STUN 等：端口固定，必须端口+指纹双重验证
VARIABLE_PORT_VALIDATORS = {
    'SSDP':       _is_valid_ssdp,       # HTTP/1.1 200 OK + UPnP 特征，误报率极低
    'WSD':        _is_valid_wsd,        # ProbeMatch XML，误报率极低
    'BitTorrent': _is_valid_bittorrent, # bencode 'd' + DHT key + 以 'e' 结尾，误报率低
}

# STRICT_PAYLOAD_VALIDATORS 向后兼容别名
STRICT_PAYLOAD_VALIDATORS = VARIABLE_PORT_VALIDATORS


def is_garbled_udp(payload: bytes) -> bool:
    """判断 UDP payload 是否是随机乱码（用于 garbage 检测）"""
    if len(payload) < 4:
        return True
    return entropy(payload) > 7.0


def identify_proto_by_payload(pl: bytes):
    """通过 payload 内容识别随机 sport 反射协议名。
    仅检查 WSD/SSDP/BitTorrent 3 个存在随机端口场景的协议。
    Ubiquiti 响应固定从 sport=10001 发出，不在此列。
    DNS/NTP/SNMP/Memcached/CLDAP/mDNS 等固定端口协议不在此列：
    这些服务端口固定，sport≠标准端口时基本是误判，必须端口+指纹双重验证。
    """
    if not pl or len(pl) < 4:
        return None
    for proto_name, validator in VARIABLE_PORT_VALIDATORS.items():
        try:
            if validator(pl):
                return proto_name
        except Exception:
            pass
    return None


def payload_matches_any_reflection(pl: bytes) -> bool:
    """按高危→中危→低危顺序验证，任意已知反射协议通过即返回 True"""
    for port, validator in ORDERED_REFLECTION_VALIDATORS:
        try:
            if validator(pl):
                return True
        except Exception:
            pass
    return False


# =============================================================================
# QUIC 解析
# =============================================================================

def _read_quic_varint(data: bytes, offset: int):
    """RFC 9000 §16 可变长整数解析。返回 (value, bytes_consumed) 或 None。"""
    if offset >= len(data):
        return None
    b = data[offset]
    pfx = (b & 0xC0) >> 6
    if pfx == 0:
        return b & 0x3F, 1
    if pfx == 1:
        if offset + 2 > len(data):
            return None
        return ((b & 0x3F) << 8) | data[offset + 1], 2
    if pfx == 2:
        if offset + 4 > len(data):
            return None
        v = ((b & 0x3F) << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]
        return v, 4
    # pfx == 3
    if offset + 8 > len(data):
        return None
    v = (((b & 0x3F) << 56) | (data[offset+1] << 48) | (data[offset+2] << 40) |
         (data[offset+3] << 32) | (data[offset+4] << 24) | (data[offset+5] << 16) |
         (data[offset+6] << 8)  |  data[offset+7])
    return v, 8


def parse_quic_initial(payload: bytes):
    """检测是否为 QUIC 包（严格验证）
    长头部：bit7=1，version 必须是已知 QUIC 版本，dcid_len 合理（0-20）
    短头部：bit7=0，fixed_bit=1，且 payload 必须通过熵检测（非全相同字节垃圾包）
    注：QUIC Coalesced 封装（RFC 9000 §12.2）在 Wireshark 中会拆开显示，
    这里只解析第一个 QUIC 包头，对分类逻辑无影响（sport=443 全部包均为服务端发出）
    """
    QUIC_VERSIONS = {
        0x00000001,  # QUIC v1 (RFC 9000)
        0xff00001d,  # draft-29
        0xff00001e,  # draft-30
        0xff00001f,  # draft-31
        0xff000020,  # draft-32
        0x6b3343cf,  # QUIC v2 (RFC 9369)
        0x00000000,  # Version Negotiation
    }
    try:
        if len(payload) < 7:
            return None
        first = payload[0]
        if not (first & 0x80):
            # 短头部：fixed_bit 必须为 1，且 payload 至少 21 字节
            if not (first & 0x40):
                return None
            if len(payload) < 21:
                return None
            # 短头部额外验证：payload 必须通过 Shannon 熵检测
            # 真实 QUIC 1-RTT 数据已加密，熵值应 > 6.5 bits/byte；
            # 随机伪造包即使 unique_bytes>2 也可能是低熵规律数据。
            # 同时要求最小长度 50 字节（1-RTT 帧 + packet number + 加密载荷）
            if len(payload) < 50:
                return None
            sample = payload[:64]
            if len(set(sample)) <= 4:       # 快速拒绝：字节种类极少
                return None
            from math import log2
            cnt = {}
            for b in sample:
                cnt[b] = cnt.get(b, 0) + 1
            n = len(sample)
            entropy = -sum((c/n)*log2(c/n) for c in cnt.values())
            if entropy < 6.0:               # 加密流量熵阈值（bits/byte）
                return None
            return {'long_header': False, 'conn_id': payload[1:9] if len(payload) >= 9 else b''}
        # 长头部：验证 Fixed bit（bit6 必须为 1）
        if not (first & 0x40):
            return None
        packet_type = (first & 0x30) >> 4
        version = struct.unpack('>I', payload[1:5])[0]
        if version != 0 and version not in QUIC_VERSIONS:
            return None
        dcid_len = payload[5]
        if dcid_len > 20:
            return None
        if 6 + dcid_len > len(payload):
            return None
        dcid = payload[6:6 + dcid_len]
        is_init = packet_type == 0 and version != 0
        # 对 Initial 包解析完整长度，检测 Coalesced Datagram（RFC 9000 §12.2）
        # 格式：first(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
        #       + token_len(varint) + token + packet_len(varint) + packet_data
        # 若 payload 在上述字段之后仍有剩余字节 → Coalesced（含额外 QUIC 包）
        coalesced = False
        if is_init:
            try:
                off = 6 + dcid_len          # 指向 scid_len 字节
                scid_len = payload[off]
                off += 1 + scid_len         # 跳过 scid
                r = _read_quic_varint(payload, off)
                if r:
                    token_len, n = r
                    off += n + token_len    # 跳过 token
                    r2 = _read_quic_varint(payload, off)
                    if r2:
                        pkt_len, n2 = r2
                        off += n2 + pkt_len  # 跳过包数据
                        coalesced = off < len(payload)
            except (IndexError, TypeError):
                pass
        return {
            'long_header': True,
            'packet_type': packet_type,
            'version':     version,
            'conn_id':     dcid,
            'is_initial':  is_init,
            'coalesced':   coalesced,   # True → datagram 含 coalesced 非 Initial 包
        }
    except Exception:
        return None


def is_quic_reflection_type(qi: dict) -> bool:
    """判断 QUIC 包是否属于反射报文类型（服务端→受害者方向）：
    - Version Negotiation（version=0）
    - Initial（packet_type=0）：服务端发出的 Initial（含 ServerHello），是反射报文
    - Handshake（packet_type=2）：服务端发出的 Handshake（含 Certificate）
    - Retry（packet_type=3）：服务端发出的 Retry

    注意：短头部（1-RTT）不视为反射类型，排除处理。
    注意：coalesced datagram 中服务端会同时发 Initial + Handshake，两者均是反射报文。
    区分上下文：sport=443 时 Initial 是服务端响应（反射）；
               dport=443 时 Initial 是客户端请求（诱发），由 is_initial 字段判断。
    """
    if qi is None:
        return False
    if not qi.get('long_header', True):
        return False   # 短头部：不视为反射，归 UDP Flood 处理
    version = qi.get('version', -1)
    if version == 0:
        return True   # Version Negotiation
    ptype = qi.get('packet_type', -1)
    return ptype in (0, 2, 3)  # Initial=0, Handshake=2, Retry=3


def is_srcip_concentrated(pkts, threshold=50):
    """判断一批包的 srcIP 是否集中（反射诱发特征）：
    - 单个 srcIP 包数 ≥ threshold，或
    - IPv4：某个 /24 网段内所有 srcIP 的总包数 ≥ threshold
    - IPv6：某个 /48 前缀内所有 srcIP 的总包数 ≥ threshold
    """
    from collections import Counter
    import ipaddress
    ip_ctr = Counter(p['src_ip'] for p in pkts)
    # 单IP集中
    if any(cnt >= threshold for cnt in ip_ctr.values()):
        return True

    def subnet_key(ip):
        """IPv4 取 /24（前3段），IPv6 取 /48（前48位）。"""
        if ':' in ip:
            try:
                return str(ipaddress.IPv6Network(ip + '/48', strict=False).network_address)
            except Exception:
                return ip
        return '.'.join(ip.split('.')[:3])

    # 网段集中：计算每个网段的总包数
    subnet_pkt_ctr = Counter()
    for ip, cnt in ip_ctr.items():
        subnet_pkt_ctr[subnet_key(ip)] += cnt
    return any(cnt >= threshold for cnt in subnet_pkt_ctr.values())


# =============================================================================
# 主分类逻辑
# =============================================================================

class Classifier:
    def __init__(self, namer, cfg, http_ports, https_ports,
                 botnet_threshold, slow_win_threshold, ja4_blacklist=None):
        self.namer             = namer
        self.wl                = Whitelist(cfg)
        self.http_ports        = http_ports
        self.https_ports       = https_ports
        self.all_app_ports     = http_ports | https_ports
        self.botnet_threshold  = botnet_threshold
        self.slow_win          = slow_win_threshold
        self.ja4_blacklist     = ja4_blacklist or set()   # JA4 恶意指纹集合
        self.written           = 0

    def save(self, subdir, dst_ip, suffix, pkts, verbose=False, min_pkts=0):
        if not pkts:
            return
        pairs = dedup_to_pairs(pkts)
        if not pairs:
            return
        # min_pkts 可能来自 _c() 返回 None（yaml 缺少该 key），兜底为 0
        if min_pkts is None:
            min_pkts = 0
        if min_pkts > 0 and len(pairs) < min_pkts:
            return
        # 根据包的 IP 版本自动在 subdir 末尾插入 IPv4/ 或 IPv6/
        # 同一批包应为同一 IP 版本（分类器按 ip_ver 分流后调用 save）
        ip_ver = pkts[0].get('ip_ver', 4)
        ver_subdir = f'{subdir}/IPv{ip_ver}'
        # 用第一个包的时间戳作为文件名日期
        # 直接用 pcap 原始 Unix 时间戳整除86400取日期，不做任何时区转换
        _ts_day = int(pkts[0]['ts']) // 86400  # 距 1970-01-01 的天数
        _epoch  = datetime.date(1970, 1, 1)
        date_str = (_epoch + datetime.timedelta(days=_ts_day)).strftime('%Y%m%d')
        # IPv6 地址含冒号，替换为下划线以保证文件名合法
        safe_dst = dst_ip.replace(':', '_')
        path = self.namer.get_path(ver_subdir, safe_dst, suffix, date_str)
        write_pcap(path, pairs)
        self.written += 1
        if verbose:
            print(f'    [写] {ver_subdir}/{os.path.basename(path)}  ({len(pairs)}包)')

    # ──────────────────────────────────────────────────────────────────────────
    # 一、网络层泛洪
    # ──────────────────────────────────────────────────────────────────────────

    def classify_syn_flood(self, parsed, verbose):
        """SYN Flood，基于 dstIP。
        需求2收紧：仅保留会话中没有 ACK 跟进的 SYN 包（单报文泛洪）。
        判定方法：同一四元组 (src_ip,sport,dst_ip,dport) 存在任意 ACK 包（SYN=0,ACK=1）
                  则视为建立会话，该四元组的 SYN 包排除出泛洪。
        按 ip_ver 分流后分别 save，自动进入 IPv4/ 或 IPv6/ 子目录。
        """
        # 第一遍：收集所有存在 ACK 跟进的四元组
        session_has_ack = set()
        for p in parsed:
            if p['proto'] != 6 or not p['tcp']:
                continue
            t = p['tcp']
            if t['ACK'] and not t['SYN']:   # 有 ACK（非 SYN-ACK）则视为会话已建立
                session_has_ack.add((p['src_ip'], p['sport'], p['dst_ip'], p['dport']))

        # 第二遍：收集 SYN（SYN=1, ACK=0），排除有 ACK 跟进的四元组
        by_dst     = collections.defaultdict(list)  # (dst_ip, ip_ver) -> pkts
        ecn_by_dst = collections.defaultdict(list)

        for p in parsed:
            if p['proto'] != 6 or not p['tcp']:
                continue
            t = p['tcp']
            if not (t['SYN'] and not t['ACK']):
                continue
            key4 = (p['src_ip'], p['sport'], p['dst_ip'], p['dport'])
            if key4 in session_has_ack:
                continue   # 该会话有后续 ACK，不是单报文泛洪
            di  = p['dst_ip']
            ver = p.get('ip_ver', 4)
            dk  = (di, ver)
            if t['ECE'] and t['CWR']:
                ecn_by_dst[dk].append(p)
            else:
                by_dst[dk].append(p)

        # 普通 SYN Flood 子分类
        for (dst_ip, ver), pkts in by_dst.items():
            small, large, common = [], [], []
            for p in pkts:
                t = p['tcp']
                has_opt  = len(t['options']) > 0
                has_data = len(t['payload']) > 0   # largeSYN 定义：带任意 payload 的 SYN（≥1 字节）
                if has_data:
                    large.append(p)
                elif not has_opt:
                    small.append(p)
                else:
                    common.append(p)

            types_present = sum([bool(small), bool(large), bool(common)])
            if types_present >= 2:
                self.save('Volumetric Attack/TCP/SYN Flood', dst_ip,
                          'comboSYN', pkts, verbose, _c('min_pkts','default'))
            else:
                if small:
                    self.save('Volumetric Attack/TCP/SYN Flood', dst_ip,
                              'smallSYN', small, verbose, _c('min_pkts','default'))
                if large:
                    self.save('Volumetric Attack/TCP/SYN Flood', dst_ip,
                              'largeSYN', large, verbose, _c('min_pkts','default'))
                if common:
                    self.save('Volumetric Attack/TCP/SYN Flood', dst_ip,
                              'commonSYN', common, verbose, _c('min_pkts','default'))

            # botnet 检测
            src_ctr = collections.Counter(p['src_ip'] for p in pkts)
            botnet_pkts = [p for p in pkts
                           if src_ctr[p['src_ip']] >= self.botnet_threshold]
            if botnet_pkts:
                self.save('Volumetric Attack/TCP/SYN Flood', dst_ip,
                          'botnetattack', botnet_pkts, verbose, _c('min_pkts','default'))

        # SYN-ECE-CWR Flood（≥50包）
        for (dst_ip, ver), pkts in ecn_by_dst.items():
            if len(pkts) >= 50:
                self.save('Volumetric Attack/TCP/SYN Flood', dst_ip,
                          'SYN-ECE-CWR', pkts, verbose)

    def classify_tcp_flood(self, parsed, verbose):
        """TCP Flood 各子类，基于 dstIP。
        需求2收紧（SYN-ACK）：仅保留会话中没有后续 ACK 的 SYN-ACK 包。
        需求3收紧（ACK/FIN-ACK/RST）：仅保留无法命中已建立会话的后续报文。
          "已建立会话"定义：同一四元组 (src_ip,sport,dst_ip,dport) 在 parsed 中
          存在 SYN（SYN=1,ACK=0）或 SYN-ACK（SYN=1,ACK=1）包。
        按 ip_ver 分流后分别 save，自动进入 IPv4/ 或 IPv6/ 子目录。
        """
        # ── 预计算辅助集合 ────────────────────────────────────────────────────
        # 1. SYN-ACK 收紧：同四元组存在 ACK（非SYN-ACK）则视为已完成握手
        synack_has_ack = set()   # 四元组：有后续 ACK
        # 2. ACK/FIN-ACK/RST 收紧：同四元组存在 SYN 或 SYN-ACK 则视为有效会话
        has_established = set()  # 四元组：存在 SYN 或 SYN-ACK
        # 3. DupACK-Flood 专用：仅纯 SYN（客户端→服务端方向）建立的会话
        #    不含 SYN-ACK（服务端→客户端），避免将服务端反向纯ACK误判为DupACK
        dup_ack_established = set()

        for p in parsed:
            if p['proto'] != 6 or not p['tcp']:
                continue
            t  = p['tcp']
            k4 = (p['src_ip'], p['sport'], p['dst_ip'], p['dport'])
            if t['SYN']:
                has_established.add(k4)   # SYN 或 SYN-ACK 均标记
            if t['SYN'] and not t['ACK']:
                dup_ack_established.add(k4)   # 仅纯 SYN（不含 SYN-ACK）
            if t['ACK'] and not t['SYN']:
                synack_has_ack.add(k4)

        # TCP Flood 目录（SYN-ACK / RST / FIN-ACK）
        flood_cats = {
            'SYN-ACK': collections.defaultdict(list),
            'RST':     collections.defaultdict(list),
            'FIN-ACK': collections.defaultdict(list),
        }
        # ACK Flood 目录（纯ACK / URG-ACK / PSH-ACK / PSH-ACK-CWR / PSH-ACK-ECE / consistentcontent）
        ack_cats = {
            'ACK':                       collections.defaultdict(list),
            'URG-ACK':                   collections.defaultdict(list),
            'PSH-ACK':                   collections.defaultdict(list),   # 无 SYN 建连的 PSH-ACK（带 payload 的伪 HTTP 请求等）
            'PSH-ACK-CWR':               collections.defaultdict(list),
            'PSH-ACK-ECE':               collections.defaultdict(list),
            'consistentcontent-payload': collections.defaultdict(list),
        }
        # DupACK-Flood 专用桶：已建立会话（四元组有SYN）中的纯ACK包
        # 与 ack_cats['ACK'] 互斥：有SYN的会话走这里，无SYN的走ack_cats['ACK']
        dup_ack_estab   = collections.defaultdict(list)
        # 记录触发 DupACK 的四元组（攻击端→受害端方向），用于后处理重建完整会话
        # key = (dst_ip, ver)，value = set of k4（src_ip, sport, dst_ip, dport）
        dup_session_k4s = collections.defaultdict(set)

        for p in parsed:
            if p['proto'] != 6 or not p['tcp']:
                continue
            t   = p['tcp']
            di  = p['dst_ip']
            ver = p.get('ip_ver', 4)
            dk  = (di, ver)
            k4  = (p['src_ip'], p['sport'], p['dst_ip'], p['dport'])

            # 注：sport 过滤改在 save 阶段做（按 sport 集中度区分 SYN-ACK Flood 与 TCP Reflection）
            # SYN-ACK Flood 定义为 spoofed-IP flood：srcIP 与 sport 都随机变化
            # TCP Reflection 定义：sport 相对固定（集中在常见服务端口 21/22/53/80/443 等）
            # 这里不在包级别过滤，让 sport=80/443 的包都先进入 flood_cats['SYN-ACK'] 桶，
            # 然后在写出时按"单一 sport 占比 ≥ 80% 视为反射特征"统一过滤，避免双写。
            # dport=80/443/8080/8443 流量原则上让给应用层分类，但仅限"已建立会话"的包
            # 关键判据：合法 HTTP/HTTPS 必须经过 SYN→SYN-ACK→ACK 三次握手才能发请求，
            # 因此 4 元组无 SYN 的任何 ACK/PSH-ACK/FIN-ACK 等都不可能是合法 HTTP 流量。
            # 这类无 SYN 的"伪 HTTP 流量"是典型 ACK/PSH-ACK Flood，应归本分类器。
            # 注：has_established 由前置预处理填充，含 SYN 和 SYN-ACK 两类四元组
            if p['dport'] in (80, 443, 8080, 8443) and k4 in has_established:
                continue

            # SYN-ACK Flood（收紧：该四元组无后续 ACK）
            if t['SYN'] and t['ACK']:
                if k4 not in synack_has_ack:
                    flood_cats['SYN-ACK'][dk].append(p)
                continue

            # 以下均为非 SYN 包，需求3：排除有已建立会话的四元组
            if k4 in has_established:
                # DupACK-Flood 例外：仅当四元组来自纯SYN（客户端方向）建立的会话
                # 才将纯ACK包收入专用桶，供后处理检测重复 ack_n。
                # 使用 dup_ack_established（纯SYN-only集合）而非 has_established，
                # 避免服务端SYN-ACK建立的反向四元组被误认为DupACK候选。
                if k4 in dup_ack_established:
                    if (t['ACK'] and not t['SYN'] and not t['PSH']
                            and not t['FIN'] and not t['RST']
                            and not t['URG'] and not t['CWR'] and not t['ECE']
                            and not t['payload']):
                        dup_ack_estab[dk].append(p)
                        dup_session_k4s[dk].add(k4)  # 记录该四元组，用于后处理重建完整会话
                continue  # 其余已建立会话包（FIN/RST/PSH等）跳过

            # FIN-ACK Flood
            if t['FIN'] and t['ACK'] and not t['SYN']:
                flood_cats['FIN-ACK'][dk].append(p)
            # RST Flood
            elif t['RST'] and not t['SYN']:
                flood_cats['RST'][dk].append(p)
            # PSH-ACK-CWR（≥50包归 ACK Flood）
            elif t['PSH'] and t['ACK'] and t['CWR'] and not t['SYN']:
                ack_cats['PSH-ACK-CWR'][dk].append(p)
            # PSH-ACK-ECE（≥50包归 ACK Flood）
            elif t['PSH'] and t['ACK'] and t['ECE'] and not t['SYN']:
                ack_cats['PSH-ACK-ECE'][dk].append(p)
            # URG-ACK Flood
            elif t['URG'] and t['ACK'] and not t['SYN']:
                ack_cats['URG-ACK'][dk].append(p)
            # PSH-ACK Flood（无 SYN 建连的带 payload ACK，常见于伪 HTTP 请求型 ACK Flood）
            # 命中前提：四元组无 SYN（前面 has_established 门控已确保），dport 任意
            elif t['PSH'] and t['ACK'] and not t['SYN'] and not t['FIN'] and not t['RST']:
                ack_cats['PSH-ACK'][dk].append(p)
            # 纯 ACK（无 SYN/PSH/FIN/RST/URG/CWR/ECE）
            elif (t['ACK'] and not t['SYN'] and not t['PSH']
                  and not t['FIN'] and not t['RST']
                  and not t['URG'] and not t['CWR'] and not t['ECE']):
                pl = t['payload']
                if pl and len(set(pl)) <= 2:
                    ack_cats['consistentcontent-payload'][dk].append(p)
                else:
                    ack_cats['ACK'][dk].append(p)

        # TCP Flood 写出（需 srcIP 或 sport 多样）
        # SYN-ACK 类目额外做 sport 集中度判定，与 TCP Reflection 分流，避免双写
        for cat, by_dst in flood_cats.items():
            for (dst_ip, ver), pkts in by_dst.items():
                src_ips   = {p['src_ip'] for p in pkts}
                src_ports = {p['sport']  for p in pkts}

                # SYN-ACK Flood vs TCP Reflection 分流：
                # SYN-ACK Flood = spoofed-IP flood，srcIP 和 sport 都"随机"
                #                 sport 通常是随机高端口（非已知服务端口）
                # TCP Reflection = sport 是真实服务的开放端口（21/22/53/80/443 等）
                #                  攻击者可能同时利用多个服务端口的反射器，
                #                  所以 sport 集中度可能不高（如 80/443/22 各占 1/3），
                #                  但全部落在 REFLECTION_PORTS_TCP 集合内
                # 判据：sport ∈ REFLECTION_PORTS_TCP 的包占比 ≥ 80% → 让 TCP Reflection 处理
                # （注：单 sport 100% 集中也满足此判据；本判据更宽松、更准确）
                if cat == 'SYN-ACK':
                    _refl_n = sum(1 for p in pkts if p['sport'] in REFLECTION_PORTS_TCP)
                    if _refl_n / len(pkts) >= 0.8:
                        continue   # sport 全在服务端口 → TCP Reflection 负责，避免双写

                if len(src_ips) > 1 or len(src_ports) > 1:
                    if cat == 'SYN-ACK':
                        self.save('Volumetric Attack/TCP/SYN-ACK', dst_ip,
                                  cat, pkts, verbose, _c('min_pkts','default'))
                    else:
                        self.save('Volumetric Attack/TCP/TCP Flood', dst_ip,
                                  cat, pkts, verbose, _c('min_pkts','default'))

        # ── DupACK-Flood 后处理：仅检测已建立会话（有SYN）中的重复 ack_n ────────
        # 识别条件：
        #   1. 四元组存在 SYN（has_established）—— 必须是完整握手建立的会话
        #   2. 该 (dst_ip,ver) 下已建立会话的纯 ACK 包中，
        #      ack_n 值出现≥3次的包占比>80%
        # 无SYN的纯ACK包（ack_cats['ACK']）保持归普通 ACK Flood，不做DupACK判定
        dup_ack_by_dst = collections.defaultdict(list)

        for (dst_ip, ver), pkts in dup_ack_estab.items():
            if len(pkts) < 50:
                continue
            ack_n_counter = collections.Counter(p['tcp']['ack_n'] for p in pkts)
            dup_ack_nums  = {n for n, c in ack_n_counter.items() if c >= 3}
            dup_pkts      = [p for p in pkts if p['tcp']['ack_n'] in dup_ack_nums]
            if len(dup_pkts) / len(pkts) > 0.8:
                dup_ack_by_dst[(dst_ip, ver)] = pkts

        # DupACK-Flood 写出（归入 TCP State Exhaustion Attack，区别于无会话状态的 ACK Flood）
        # 从 parsed 中重建完整会话（双向），确保输出 pcap 包含：
        #   SYN/SYN-ACK 握手、服务端数据包、DupACK 攻击包、FIN/RST 结束包
        # 这样 Wireshark 可直接用 tcp.flags.syn==1 看到建连过程，确认是已建立会话的攻击
        for (dst_ip, ver), pkts in dup_ack_by_dst.items():
            target_k4s = dup_session_k4s.get((dst_ip, ver), set())
            if target_k4s:
                # 匹配正向（攻击端→受害端）和反向（受害端→攻击端）两个方向的所有包
                full_pkts = sorted(
                    (p for p in parsed
                     if p['proto'] == 6 and p['tcp']
                     and ((p['src_ip'], p['sport'], p['dst_ip'], p['dport']) in target_k4s
                          or (p['dst_ip'], p['dport'], p['src_ip'], p['sport']) in target_k4s)),
                    key=lambda p: p['ts']
                )
            else:
                full_pkts = pkts  # 兜底：无k4记录时退化为仅DupACK包
            self.save('TCP State Exhaustion Attack/DupACK-Flood', dst_ip,
                      'DupACK-Flood', full_pkts, verbose)

        # ACK Flood 写出（单独目录，≥50包）
        for cat, by_dst in ack_cats.items():
            for (dst_ip, ver), pkts in by_dst.items():
                if len(pkts) >= 50:
                    self.save('Volumetric Attack/TCP/ACK Flood', dst_ip,
                              cat, pkts, verbose)

    def classify_icmp_flood(self, parsed, verbose):
        by_dst = collections.defaultdict(list)
        for p in parsed:
            # proto=1 (ICMPv4) 或 proto=58 (ICMPv6)
            if p['proto'] in (1, 58) and p['icmp']:
                by_dst[(p['dst_ip'], p.get('ip_ver', 4))].append(p)
        for (dst_ip, ver), pkts in by_dst.items():
            self.save('Volumetric Attack/ICMP/ICMP Flood', dst_ip,
                      'ICMP', pkts, verbose, _c('min_pkts','default'))

    def classify_gre_flood(self, parsed, verbose):
        """GRE Flood（proto=47）。
        按 GRE 内层 Protocol Type 细分三个子类：
          GRE-IPv6-Flood  — 0x86DD，GRE 封装 IPv6
          GRE-PPTP-Flood  — 0x880b，增强型 GRE（PPTP/RFC2637），内层为 PPP
          GRE-Flood       — 其余内层协议，通用 GRE 泛洪
        """
        by_ipv6  = collections.defaultdict(list)
        by_pptp  = collections.defaultdict(list)
        by_other = collections.defaultdict(list)

        for p in parsed:
            if p['proto'] != 47:
                continue
            dk = (p['dst_ip'], p.get('ip_ver', 4))
            inner_proto = _parse_gre_proto(p['ip']['payload']) if p['ip'] else None
            if inner_proto == 0x86DD:
                by_ipv6[dk].append(p)
            elif inner_proto == 0x880b:
                by_pptp[dk].append(p)
            else:
                by_other[dk].append(p)

        min_p = _c('min_pkts', 'default')
        for (dst_ip, ver), pkts in by_ipv6.items():
            self.save('Volumetric Attack/IP Flood/GRE-IPv6-Flood', dst_ip,
                      'GRE-IPv6-Flood', pkts, verbose, min_p)
        for (dst_ip, ver), pkts in by_pptp.items():
            self.save('Volumetric Attack/IP Flood/GRE-PPTP-Flood', dst_ip,
                      'GRE-PPTP-Flood', pkts, verbose, min_p)
        for (dst_ip, ver), pkts in by_other.items():
            self.save('Volumetric Attack/IP Flood/GRE Flood', dst_ip,
                      'GRE-Flood', pkts, verbose, min_p)

    def classify_tunnel_flood(self, parsed, verbose):
        """IPv6-over-IPv4 6in4 隧道洪泛（外层 IPv4 proto=41）。

        攻击者将 IPv6 数据帧封装在 IPv4 proto=41（6in4，RFC 4213）报文中，
        发向目标 IP，实现两个目标：
          1. 绕过仅匹配 IPv4 层协议的防火墙 ACL（防火墙看到 proto=41，规则不触发）
          2. 以全速率发送大包饱和目标带宽

        按内层 IPv6 next_hdr 区分三个子类：
          6in4-TCP-Flood     — next_hdr=6
          6in4-UDP-Flood     — next_hdr=17
          6in4-ICMPv6-Flood  — next_hdr=58
        """
        by_tcp    = collections.defaultdict(list)
        by_udp    = collections.defaultdict(list)
        by_icmpv6 = collections.defaultdict(list)
        by_other  = collections.defaultdict(list)

        for p in parsed:
            # 仅处理外层 IPv4 + proto=41（6in4）
            if p.get('ip_ver') != 4 or p['proto'] != 41 or not p['ip']:
                continue
            dk = (p['dst_ip'], 4)  # 外层 IP 版本固定为 4

            # 内层 IPv6 数据在外层 IP 的 payload 里
            inner = parse_ipv6(p['ip']['payload'])
            if inner is None:
                by_other[dk].append(p)
                continue

            nh = inner['proto']   # parse_ipv6 返回的最终 next_hdr
            if nh == 6:
                by_tcp[dk].append(p)
            elif nh == 17:
                by_udp[dk].append(p)
            elif nh == 58:
                by_icmpv6[dk].append(p)
            else:
                by_other[dk].append(p)

        base  = 'Volumetric Attack/IPv6 Tunnel Flood'
        min_p = _c('min_pkts', 'default')
        for (dst_ip, ver), pkts in by_tcp.items():
            self.save(f'{base}/6in4-TCP-Flood',    dst_ip, '6in4-TCP-Flood',    pkts, verbose, min_p)
        for (dst_ip, ver), pkts in by_udp.items():
            self.save(f'{base}/6in4-UDP-Flood',    dst_ip, '6in4-UDP-Flood',    pkts, verbose, min_p)
        for (dst_ip, ver), pkts in by_icmpv6.items():
            self.save(f'{base}/6in4-ICMPv6-Flood', dst_ip, '6in4-ICMPv6-Flood', pkts, verbose, min_p)
        # 内层非 TCP/UDP/ICMPv6 的 6in4 包归入通用目录（极少见）
        for (dst_ip, ver), pkts in by_other.items():
            self.save(f'{base}/6in4-Other-Flood',  dst_ip, '6in4-Other-Flood',  pkts, verbose, min_p)

        # ── Teredo（IPv6-in-UDP，RFC 4380）──────────────────────────────────
        # Teredo 服务端口为 3544（sport=3544 即攻击者通过 Teredo 服务器发出）
        # 内层 IPv6/ICMPv6 type=134（Router Advertisement）→ Teredo-RA-Flood
        # 攻击效果：绕过 IPv4 防火墙，向受害者注入伪造 RA，
        #   扰乱其 IPv6 默认路由（router_lifetime=0 撤销路由 + 注入垃圾前缀）
        teredo_ra    = collections.defaultdict(list)   # ICMPv6 RA (type=134)
        teredo_ns    = collections.defaultdict(list)   # ICMPv6 NS/NA (type=135/136)
        teredo_other = collections.defaultdict(list)   # 其余内层协议

        for p in parsed:
            if p['proto'] != 17 or not p['udp'] or p.get('ip_ver') != 4:
                continue
            if p['sport'] != 3544:   # Teredo 服务端口
                continue
            dk = (p['dst_ip'], 4)
            udp_pl = p['udp']['payload']
            off    = _parse_teredo_offset(udp_pl)
            inner  = parse_ipv6(udp_pl[off:])
            if inner is None:
                teredo_other[dk].append(p)
                continue
            nh = inner['proto']
            if nh == 58:  # ICMPv6
                icmp6_pl = inner['payload']
                t = icmp6_pl[0] if icmp6_pl else 0
                if t == 134:                  # Router Advertisement
                    teredo_ra[dk].append(p)
                elif t in (135, 136):         # Neighbor Solicitation / Advertisement
                    teredo_ns[dk].append(p)
                else:
                    teredo_other[dk].append(p)
            else:
                teredo_other[dk].append(p)

        for (dst_ip, ver), pkts in teredo_ra.items():
            self.save(f'{base}/Teredo-RA-Flood', dst_ip, 'Teredo-RA-Flood', pkts, verbose, min_p)
        for (dst_ip, ver), pkts in teredo_ns.items():
            self.save(f'{base}/Teredo-NS-Flood', dst_ip, 'Teredo-NS-Flood', pkts, verbose, min_p)
        for (dst_ip, ver), pkts in teredo_other.items():
            self.save(f'{base}/Teredo-Other-Flood', dst_ip, 'Teredo-Other-Flood', pkts, verbose, min_p)

    def classify_ip_flood(self, parsed, verbose):
        """IP Flood / IP Fragment Flood：非 GRE/TCP/UDP/ICMP(v4+v6) 包"""
        KNOWN_PROTOS = {1, 6, 17, 41, 47, 58}  # ICMP / TCP / UDP / 6in4 / GRE / ICMPv6
        ip_flood_by_dst   = collections.defaultdict(list)
        ip_frag_by_dst    = collections.defaultdict(list)

        for p in parsed:
            if not p['ip']:
                continue
            proto = p['proto']
            if proto in KNOWN_PROTOS:
                continue
            dk = (p['dst_ip'], p.get('ip_ver', 4))
            if p['ip']['is_fragment']:
                ip_frag_by_dst[dk].append(p)
            else:
                ip_flood_by_dst[dk].append(p)

        dir_base = 'Volumetric Attack/IP Flood/IP Flood'
        for (dst_ip, ver), pkts in ip_flood_by_dst.items():
            self.save(dir_base, dst_ip, 'IP-Flood', pkts, verbose, _c('min_pkts','fragment'))
        for (dst_ip, ver), pkts in ip_frag_by_dst.items():
            self.save(dir_base, dst_ip, 'Fragment', pkts, verbose, _c('min_pkts','fragment'))

    def classify_udp_flood(self, parsed, verbose):
        """UDP Flood 7 种子类，各写各的，基于 dstIP"""
        # 原则3：UDP 反射优先级高于 UDP Flood
        # 排除规则：
        # 1. sport 在已知反射端口且通过 response validator → 归反射
        # 2. sport 不在已知端口但 payload 通过严格 validator（变端口反射）→ 归反射
        # 3. sport 不在已知端口，dport 在已知端口，且通过 AMPLIFICATION_REQUEST_VALIDATORS → 归诱发
        # 4. sport=3544（Teredo 服务端口）→ 由 classify_tunnel_flood 处理，此处跳过
        by_dst = collections.defaultdict(list)
        for p in parsed:
            if p['proto'] != 17 or not p['udp']:
                continue
            sport = p['sport']
            if sport == 3544:          # Teredo（IPv6-over-UDP）→ 已由隧道分类器处理
                continue
            dport = p['dport']
            pl    = p['udp']['payload']
            if sport in REFLECTION_PORTS_UDP:
                # 端口+协议双条件：sport 在已知反射端口，还需 payload 通过 response validator
                if sport == 443:
                    qi = parse_quic_initial(pl)
                    if qi is not None and is_quic_reflection_type(qi):
                        continue  # QUIC 长头部反射（VN/Retry/Handshake），走反射分类
                    # 短头部或无效 QUIC → 落 UDP Flood
                else:
                    validator = REFLECTION_VALIDATORS.get(sport)
                    if validator is None or validator(pl):
                        continue  # validator 通过 → 归反射；无 validator → 按端口归反射
                    # validator 失败：payload 协议兜底识别
                    proto_by_payload = identify_proto_by_payload(pl)
                    if proto_by_payload or _is_sip_response(pl):
                        continue  # payload 识别出反射响应协议 → 归反射
                # 原则1：sport validator 失败时，仅当 dport 有明确 request validator 且通过才跳过
                if dport in AMPLIFICATION_REQUEST_VALIDATORS:
                    if AMPLIFICATION_REQUEST_VALIDATORS[dport](pl):
                        continue  # 合法诱发报文 → 交给 classify_udp_reflection
                elif dport in (443, 5004, 5005, 1701, 25565):
                    continue  # 特殊端口由 classify_udp_reflection 处理
            else:
                # sport 不在已知端口
                if dport in REFLECTION_PORTS_UDP:
                    # 原则2：用 AMPLIFICATION_REQUEST_VALIDATORS 决定是否跳过（收紧逻辑）
                    _dport_valid = False
                    if dport == 443:
                        qi2 = parse_quic_initial(pl)
                        _dport_valid = (qi2 is not None)
                    elif dport == 53:
                        dns2 = parse_dns(pl)
                        # 任何合法 DNS query 都跳过 flood，交给 classify_dns
                        _dport_valid = (dns2 is not None and not dns2['is_response'])
                    elif dport in (5004, 5005):
                        _dport_valid = _is_valid_rtcp(pl)
                    elif dport == 1701:
                        _dport_valid = _is_valid_l2tp(pl)
                    elif dport == 25565:
                        _dport_valid = (len(pl) >= 7 and pl[0:2] == b'\xfe\xfd')
                    elif dport in AMPLIFICATION_REQUEST_VALIDATORS:
                        # 原则2：用对应的 request validator 校验，通过才跳过
                        _dport_valid = AMPLIFICATION_REQUEST_VALIDATORS[dport](pl)
                    # 其余端口（无明确 request validator）：不跳过，落入 flood pool
                    if _dport_valid:
                        continue   # 合法诱发/应用层包 → 交给 classify_udp_reflection/classify_dns
                    # validator 失败：随机 payload 打已知端口，落入 flood pool
                elif identify_proto_by_payload(pl) is not None or _is_sip_response(pl):
                    # sport/dport 均不在已知端口，但 payload 被识别为已知反射响应协议
                    # → 变端口反射，交给 classify_udp_reflection 处理
                    # 注意：SIP request 不满足 _is_sip_response，不会被错误排出 flood pool
                    continue
            by_dst[p['dst_ip']].append(p)

        for dst_ip, pkts in by_dst.items():
            # ── 兜底：同一 sport 包数 ≥ 500，归 fixedsport_XX ──────────────────
            # 避免变端口 UDP 反射或未知大流量漏分类
            sport_groups = collections.defaultdict(list)
            for p in pkts:
                sport_groups[p['sport']].append(p)
            for sport, sport_pkts in sport_groups.items():
                if len(sport_pkts) >= _c('udp_flood','fixedsport_min_pkts'):
                    self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                              f'fixedsport_{sport}', sport_pkts, verbose)

            payloads   = [p['udp']['payload'] for p in pkts]
            lengths    = [len(pl) for pl in payloads]
            src_ips    = [p['src_ip'] for p in pkts]
            src_ports  = [p['sport']  for p in pkts]

            # 按流分组 (src_ip,sport,dst_ip,dport)
            flows = collections.defaultdict(list)
            for p in pkts:
                flows[(p['src_ip'], p['sport'], p['dst_ip'], p['dport'])].append(p)

            n_flows = len(flows)
            src_ip_set   = set(src_ips)
            sport_set    = set(src_ports)
            len_set      = set(lengths)

            # ── garbage：每包一流，payload 随机变化，长度随机变化 ─────────────
            one_pkt_flows = sum(1 for fl in flows.values() if len(fl) == 1)
            if (one_pkt_flows / max(n_flows, 1) > _c('udp_flood','garbage_one_pkt_ratio')
                    and len(src_ip_set) > _c('udp_flood','garbage_src_ip_min')
                    and len(len_set) > _c('udp_flood','garbage_len_variety_min')
                    and len(set(payloads)) / max(len(payloads), 1) > _c('udp_flood','garbage_payload_unique_ratio')):
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'garbage-packet', pkts, verbose, _c('min_pkts','default'))

            # ── fixedLen：报文长度固定 ─────────────────────────────────────────
            if len(len_set) == 1:
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'fixedLen', pkts, verbose, _c('min_pkts','default'))

            # ── fixedpayload：所有报文内容相同（乱码但相同）──────────────────
            unique_payloads = set(payloads)
            if len(unique_payloads) == 1:
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'fixedpayload', pkts, verbose, _c('min_pkts','default'))

            # ── signature_payload：payload 有固定前缀特征（前8字节相同）────────
            prefixes = set(pl[:8] for pl in payloads if len(pl) >= 8)
            if len(prefixes) == 1 and len(unique_payloads) > 1:
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'signature-payload', pkts, verbose, _c('min_pkts','default'))

            # ── consistentcontent：payload 字节内容单一（全0/全A等），
            #    防御侧取前4+中间4+后4字节三段对比，因此 payload 必须 ≥ 12 字节
            #    才能有意义地进行三段采样，短包不应归此分类
            def is_consistent(pl):
                return len(pl) >= 12 and len(set(pl)) <= 2
            if payloads and sum(1 for pl in payloads if is_consistent(pl)) / len(payloads) > _c('udp_flood','garbage_one_pkt_ratio'):
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'consistentcontent-payload', pkts, verbose, _c('min_pkts','default'))

            # ── highentropy / lowentropy：同一流多包，按流内 entropy 区分 ──────
            high_pkts, low_pkts = [], []
            for fl_pkts in flows.values():
                if len(fl_pkts) < _c('udp_flood','highentropy_flow_min_pkts'):
                    continue
                fl_payloads = [p['udp']['payload'] for p in fl_pkts]
                avg_ent = sum(entropy(pl) for pl in fl_payloads) / len(fl_payloads)
                if avg_ent > _c('udp_flood','highentropy_threshold'):
                    high_pkts.extend(fl_pkts)
                else:
                    low_pkts.extend(fl_pkts)
            if high_pkts:
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'highentropy-payload', high_pkts, verbose, _c('min_pkts','default'))
            if low_pkts:
                self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                          'lowentropy-payload', low_pkts, verbose, _c('min_pkts','default'))

    def classify_malformed(self, parsed, verbose):
        """TCP / UDP / IP Malformed，TCP细化为多个子分类，兼容 IPv4/IPv6"""
        # TCP Malformed 各子分类，key=(dst_ip, ip_ver)
        tcp_sameport   = collections.defaultdict(list)
        tcp_flagbad    = collections.defaultdict(list)   # 纯逻辑悖论 → errorTCPFlag
        tcp_evasion    = collections.defaultdict(list)   # 高级状态逃逸 → TCPFlag-Stateful-Evasion
        tcp_zeroport   = collections.defaultdict(list)
        tcp_checksum   = collections.defaultdict(list)
        tcp_sameip     = collections.defaultdict(list)
        tcp_pktlen     = collections.defaultdict(list)
        tcp_other      = collections.defaultdict(list)
        udp_mal        = collections.defaultdict(list)
        ip_mal         = collections.defaultdict(list)

        # 高级状态逃逸 flag 集合（按文档类别二定义）
        # FIN+ECN(0x051/0x091)、URG+ACK(0x030/0x031)、多位堆叠(0x0b1/0x099)等
        STATEFUL_EVASION_FLAGS = {
            0x051,   # FIN + ACK + ECE
            0x091,   # FIN + ACK + CWR
            0x031,   # FIN + ACK + URG
            0x030,   # ACK + URG
            0x038,   # PSH + ACK + URG
            0x0b1,   # FIN + ACK + URG + CWR
            0x099,   # FIN + PSH + ACK + CWR
            0x071,   # FIN + ACK + URG + ECE
            0x0d1,   # FIN + ACK + URG + CWR（含PSH）
        }

        for p in parsed:
            dst_ip = p['dst_ip']
            ver    = p.get('ip_ver', 4)
            dk     = (dst_ip, ver)

            # IP Malformed（IPv4 only：ihl/total_len 检查；IPv6 只做 same_ip 检查）
            if p['ip'] and p['proto'] not in (1, 58):
                ip = p['ip']
                reasons = []
                if ip['src_ip'] == ip['dst_ip']:
                    reasons.append('same_ip')
                if ver == 4:
                    if ip['proto'] is None or ip['ihl'] < 20:
                        reasons.append('bad_ihl')
                    if ip['total_len'] < ip['ihl']:
                        reasons.append('bad_total_len')
                if reasons:
                    ip_mal[dk].append(p)

            # TCP Malformed 细化子分类
            if p['proto'] == 6 and p['tcp']:
                t = p['tcp']
                f = t['flags']

                # HTTP 反射端口来源（sport=80/8080/8000/8888）的包已由
                # classify_http_reflection 处理，Malformed 不再接管
                HTTP_REFLECTION_SPORTS = {80, 8080, 8000, 8888}
                if p['sport'] in HTTP_REFLECTION_SPORTS:
                    continue

                if t['sport'] == 0 or t['dport'] == 0:
                    tcp_zeroport[dk].append(p); continue
                if p['src_ip'] == p['dst_ip']:
                    tcp_sameip[dk].append(p); continue
                if t['sport'] == t['dport']:
                    tcp_sameport[dk].append(p); continue

                # 包长错误（IPv4 only；IPv6 由扩展头长度决定，跳过此检查）
                if ver == 4 and p['ip']:
                    ip_total    = p['ip']['total_len']
                    ip_hdr      = p['ip']['ihl']
                    tcp_hdr_len = t.get('data_offset', 20)
                    if ip_total < ip_hdr + tcp_hdr_len:
                        tcp_pktlen[dk].append(p); continue

                # Checksum 错误（仅 IPv4，IPv6 TCP checksum 由硬件卸载时常为0）
                if ver == 4 and t.get('checksum') == 0 and not (t['SYN'] and not t['ACK']):
                    tcp_checksum[dk].append(p); continue

                # 非法 flag 组合（按文档 TCPFlag 原则严格实现）
                # 优先：高级状态逃逸类（不走 bad_flag 路径，直接分流）
                if f in STATEFUL_EVASION_FLAGS:
                    tcp_evasion[dk].append(p); continue

                bad_flag = False
                syn = t['SYN']; ack = t['ACK']; rst = t['RST']
                fin = t['FIN']; psh = t['PSH']; urg = t['URG']
                ece = t['ECE']; cwr = t['CWR']

                # 极端异常：全开/全闭
                if f == 0xFF or f == 0x00:
                    bad_flag = True
                # 核心控制位冲突：SYN=1 且任意 URG/PSH/FIN/RST 置位
                elif syn and (urg or psh or fin or rst):
                    bad_flag = True
                # RST 原则：RST 只能单独存在，或与 ACK 共存；
                # 与任何其他控制位（FIN/PSH/URG/ECE/CWR）共存均非法
                # 注意：rst and not syn 已经由上一条保证（syn+rst 已被捕获）
                elif rst and (fin or psh or urg or ece or cwr):
                    bad_flag = True
                # 基础协议违背：SYN=0 且 ACK=0 且非纯 RST（无任何合理解释）
                elif not syn and not ack and not rst and f != 0:
                    bad_flag = True
                # URG=1 且紧急指针为 0
                elif urg and t.get('urg_ptr', 1) == 0:
                    bad_flag = True
                # ACK=0 且 AckNum≠0 且非 SYN 且非 RST
                elif not ack and t['ack_n'] != 0 and not syn and not rst:
                    bad_flag = True
                # ECN 悖论1（服务端死罪）：SYN=1 ACK=1 CWR=1
                elif syn and ack and cwr:
                    bad_flag = True
                # ECN 悖论2（客户端残缺协商）：SYN=1 ACK=0 且 ECE⊕CWR=1
                elif syn and not ack and (ece ^ cwr):
                    bad_flag = True

                if bad_flag:
                    # 先判断是否属于高级状态逃逸类（STATEFUL_EVASION_FLAGS）
                    if f in STATEFUL_EVASION_FLAGS:
                        tcp_evasion[dk].append(p)
                    else:
                        tcp_flagbad[dk].append(p)
                    continue

                if f not in VALID_FLAG_COMBOS:
                    tcp_other[dk].append(p)

            # UDP Malformed
            if p['proto'] == 17 and p['udp']:
                u = p['udp']
                reasons = []
                if u['sport'] == 0 or u['dport'] == 0:
                    reasons.append('zero_port')
                if p['src_ip'] == p['dst_ip']:
                    reasons.append('same_ip')
                if u['length'] < 8:
                    reasons.append('bad_length')
                if reasons:
                    udp_mal[dk].append(p)

        dir_tcp = 'Volumetric Attack/TCP/TCP Malformed'
        for (dst_ip, ver), pkts in tcp_sameport.items():
            self.save(dir_tcp, dst_ip, 'sameport',                pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_flagbad.items():
            self.save(dir_tcp + '/error-TCPFlag', dst_ip, 'errorTCPFlag', pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_evasion.items():
            self.save(dir_tcp + '/TCPFlag-Stateful-Evasion', dst_ip,
                      'TCPFlag-Stateful-Evasion', pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_zeroport.items():
            self.save(dir_tcp, dst_ip, '0port',                   pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_checksum.items():
            self.save(dir_tcp, dst_ip, 'errorChecksum',           pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_sameip.items():
            self.save(dir_tcp, dst_ip, 'sameIP',                  pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_pktlen.items():
            self.save(dir_tcp, dst_ip, 'errorPktLen',             pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_other.items():
            self.save(dir_tcp, dst_ip, 'Malformed',               pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in udp_mal.items():
            self.save('Volumetric Attack/UDP/UDP Malformed', dst_ip,
                      'malformed', pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in ip_mal.items():
            self.save('Volumetric Attack/IP/IP Malformed', dst_ip,
                      'malformed', pkts, verbose, _c('min_pkts','default'))

    def classify_fragments(self, parsed, verbose):
        """分片攻击，兼容 IPv6 Fragment 扩展头"""
        icmp_frag = collections.defaultdict(list)
        tcp_frag  = collections.defaultdict(list)
        udp_frag  = collections.defaultdict(list)
        for p in parsed:
            if not p['ip'] or not p['ip']['is_fragment']:
                continue
            dk    = (p['dst_ip'], p.get('ip_ver', 4))
            proto = p['proto']
            if proto in (1, 58):   # ICMPv4 + ICMPv6
                icmp_frag[dk].append(p)
            elif proto == 6:
                tcp_frag[dk].append(p)
            elif proto == 17:
                udp_frag[dk].append(p)
        for (dst_ip, ver), pkts in icmp_frag.items():
            self.save('Volumetric Attack/ICMP/ICMP Flood', dst_ip,
                      'fragment', pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in tcp_frag.items():
            self.save('Volumetric Attack/TCP/TCP Flood', dst_ip,
                      'fragment', pkts, verbose, _c('min_pkts','default'))
        for (dst_ip, ver), pkts in udp_frag.items():
            self.save('Volumetric Attack/UDP/UDP Flood', dst_ip,
                      'fragment', pkts, verbose, _c('min_pkts','default'))

    # ──────────────────────────────────────────────────────────────────────────
    # 二、反射攻击
    # ──────────────────────────────────────────────────────────────────────────

    def classify_udp_reflection(self, parsed, verbose):
        """UDP 反射 + 诱发报文分类

        识别原则：
        (1) 端口固定的反射：按 sport + 协议特征识别
            - QUIC(443)：sport=443 + QUIC 反射类型（VN/Retry/Handshake/短头部）
            - 其他已知端口：sport 在 REFLECTION_PORTS_UDP + RFC validator 通过
        (2) 端口不固定的反射：payload 关键字识别（WSD/SSDP/STUN/WireGuard/BitTorrent）
        (3) 诱发报文：dport 在已知反射端口 + srcIP 集中（单IP或/24网段≥50包）
            - 对于 dport=443/53/5060/5061 等特殊端口，srcIP 不集中则归 UDP Flood
        (4) 识别优先级：高危 → 中危 → 低危
        """
        by_dst     = collections.defaultdict(lambda: collections.defaultdict(list))
        amp_by_dst = collections.defaultdict(lambda: collections.defaultdict(list))

        # 按 (dport, dst_ip) 暂存待判断的诱发报文候选，用于 srcIP 集中度统计
        # key=(dport, dst_ip), value=list of (proto_name, p, extra_check_passed)
        amp_candidates = collections.defaultdict(list)

        for p in parsed:
            if p['proto'] != 17 or not p['udp']:
                continue
            if p['ip'] and p['ip']['frag_off'] > 0:
                continue
            sport = p['sport']
            dport = p['dport']
            pl    = p['udp']['payload']

            # ── 已知反射端口（sport 固定）────────────────────────────────────
            if sport in REFLECTION_PORTS_UDP:
                # QUIC(443) sport=443 的反射响应由 classify_quic 处理，此处跳过
                if sport == 443:
                    pass
                else:
                    # 优先级原则：validator 通过 → 归端口映射协议
                    # 例外：纯长度 validator（Lantronix/IPMI/Dropbox/ARD 等 len>=N）
                    # 区分能力极弱，若 payload 精确匹配 VARIABLE_PORT_VALIDATORS 中的协议则以 payload 为准
                    # 严格 validator（DNS/NTP/SNMP/STUN 等）通过后绝不用 payload 覆盖
                    # 文档高危优先：SSDP→DNS→mDNS→NTP→Memcached→CLDAP→SNMP→…→Ubiquiti
                    WEAK_VALIDATORS = {
                        30718, 17500, 138, 623, 3283, 9, 17,  # len>=N 纯长度 validator
                    }
                    validator = REFLECTION_VALIDATORS.get(sport)
                    validator_pass = (validator is None or validator(pl))

                    if validator_pass and sport not in WEAK_VALIDATORS:
                        # 严格 validator 通过 → 直接归端口映射协议，不做 payload 覆盖
                        by_dst[p['dst_ip']][REFLECTION_PORTS_UDP[sport]].append(p)
                    else:
                        # validator 失败，或是宽松 validator → 用 VARIABLE_PORT_VALIDATORS 识别
                        proto_by_payload = identify_proto_by_payload(pl)
                        if proto_by_payload and proto_by_payload != REFLECTION_PORTS_UDP.get(sport):
                            by_dst[p['dst_ip']][proto_by_payload].append(p)
                        elif validator_pass:
                            # 宽松 validator 通过但 payload 未匹配更精确协议 → 归端口映射
                            by_dst[p['dst_ip']][REFLECTION_PORTS_UDP[sport]].append(p)
                        elif _is_sip_response(pl):
                            by_dst[p['dst_ip']]['SIP'].append(p)
                        # 其余真正识别不出的 → 落入 UDP Flood

            # ── sport 不在已知端口 ───────────────────────────────────────────
            else:
                if dport in REFLECTION_PORTS_UDP:
                    # 诱发报文候选：原则1：sport 在已知端口时已在上方处理，不会到达这里
                    # 原则2：必须是 request 报文，用 AMPLIFICATION_REQUEST_VALIDATORS 校验
                    proto_name = REFLECTION_PORTS_UDP[dport]
                    valid = False
                    if dport == 443:
                        # QUIC(443) dport=443 的请求分类由 classify_quic 处理，此处跳过
                        valid = False
                    elif dport in (5004, 5005):
                        # RTCP：诱发报文必须是合法 RTCP（ver=2，PT 有效）
                        valid = _is_valid_rtcp(pl)
                    elif dport == 1701:
                        # L2TP：诱发报文必须是控制包（T=1）
                        valid = _is_valid_l2tp(pl)
                    elif dport == 25565:
                        # Minecraft：诱发报文必须以 \xFE\xFD 魔数开头
                        valid = (len(pl) >= 7 and pl[0:2] == b'\xfe\xfd')
                    elif dport in AMPLIFICATION_REQUEST_VALIDATORS:
                        # 原则2：用该协议专属的 request validator 校验（含原则4字符串特征）
                        valid = AMPLIFICATION_REQUEST_VALIDATORS[dport](pl)
                    # 原则2：不在上述列表中的端口不识别诱发报文（无 else 通过分支）
                    if valid:
                        amp_candidates[(dport, p['dst_ip'])].append((proto_name, p))
                else:
                    # sport/dport 均不在已知端口：payload 识别随机 sport 反射（原则3）
                    proto_name = identify_proto_by_payload(pl)
                    if proto_name:
                        # 原则3修正文件名：用连字符（SSDP-randomsport）
                        by_dst[p['dst_ip']][f'{proto_name}-randomsport'].append(p)
                    # 原则2：移除 XX_{sport} 无意义分类，未识别协议直接忽略

        # ── 诱发报文：srcIP 集中度判断 ───────────────────────────────────────
        # dport=443/53/5060/5061 时，srcIP 集中在某个IP或/24网段（≥50包）
        # 才归诱发报文；否则归 UDP 应用层 Flood（由 classify_udp_flood 处理）
        # 其他已知反射端口：直接归诱发报文（不做集中度过滤）
        CONCENTRATED_CHECK_PORTS = {443, 53, 5060, 5061}
        for (dport, dst_ip), items in amp_candidates.items():
            pkts = [p for _, p in items]
            proto_name = items[0][0]
            if dport in CONCENTRATED_CHECK_PORTS:
                if is_srcip_concentrated(pkts, threshold=_c('udp_reflection','srcip_concentrated_threshold')):
                    amp_by_dst[dst_ip][proto_name].extend(pkts)
                # 不集中 → 不归诱发，让包落入 UDP Flood
            else:
                amp_by_dst[dst_ip][proto_name].extend(pkts)

        # ── 写出反射文件 ─────────────────────────────────────────────────────
        for dst_ip, protos in by_dst.items():
            for proto_name, pkts in protos.items():
                # randomsport 类无需 src_ip 集中度过滤：
                # payload validator 已提供足够的协议特征保证（如 SSDP HTTP/1.1 200 OK + UPnP）
                # UDP 反射成本远高于直接 Flood，攻击者不会用反射机制伪装 Flood
                self.save('Volumetric Attack/UDP/Reflection', dst_ip,
                          proto_name, pkts, verbose, _c('min_pkts', 'udp_reflection'))

        # ── 写出诱发报文文件 ─────────────────────────────────────────────────
        for dst_ip, protos in amp_by_dst.items():
            for proto_name, pkts in protos.items():
                self.save('Volumetric Attack/UDP/Amplification Request', dst_ip,
                          proto_name, pkts, verbose, _c('min_pkts','amp_request', default=50))

    def classify_tcp_reflection(self, parsed, verbose):
        """TCP反射：源端口在已知列表，且流量以 SYN-ACK 建立会话为前提。
        反射包含 SYN-ACK、RST-ACK 等多种类型，合并写出为单个文件。
        触发条件：
          1. SYN-ACK ≥ 1（必须有握手建立，排除纯 RST-ACK Flood）
          2. (SYN-ACK + RST-ACK) 占总包数 > 50%
          3. PSH-ACK < (SYN-ACK + RST-ACK)（响应数据包少于反射握手包）
        """
        by_dst = collections.defaultdict(list)
        for p in parsed:
            if p['proto'] != 6 or not p['tcp']:
                continue
            if p['sport'] in REFLECTION_PORTS_TCP:
                by_dst[p['dst_ip']].append(p)
        for dst_ip, pkts in by_dst.items():
            total           = len(pkts)
            synack_cnt      = sum(1 for p in pkts if p['tcp']['SYN'] and p['tcp']['ACK'])
            rst_ack_cnt     = sum(1 for p in pkts if p['tcp']['RST'] and p['tcp']['ACK']
                                  and not p['tcp']['SYN'])
            psh_ack_cnt     = sum(1 for p in pkts if p['tcp']['PSH'] and p['tcp']['ACK']
                                  and not p['tcp']['SYN'])
            reflection_cnt  = synack_cnt + rst_ack_cnt
            # 条件1：必须有 SYN-ACK（以会话建立为前提，排除纯 RST-ACK Flood）
            if synack_cnt < 1:
                continue
            # 条件2：(SYN-ACK + RST-ACK) 必须超过总包数 50%
            # 条件3：PSH-ACK 少于反射包总数
            if reflection_cnt <= total * 0.5 or psh_ack_cnt >= reflection_cnt:
                continue
            self.save('Volumetric Attack/TCP/TCP Reflection', dst_ip,
                      'TCP-Reflection', pkts, verbose, _c('min_pkts', 'default'))

    def classify_http_reflection(self, parsed, verbose):
        """HTTP 反射：审查设备/安全设备注入 HTTP 40x 响应流量打向受害者。
        攻击机制（参考 NETSCOUT ASERT）：
          攻击者向审查设备/防火墙发送伪造受害者 IP 的明文 HTTP 请求
          → 设备解析内容后注入 4xx/5xx 错误响应，具有放大效果
        识别逻辑（会话粒度）：
          1. sport 在 HTTP 端口（80/8080/8000/8888）
          2. 以 (srcIP, dport) 为会话 key
          3. 会话上含 HTTP 4xx/5xx 响应（必要条件）→ 该会话全部报文归入
          4. 不含 4xx/5xx 的会话不归入（排除纯 SYN-ACK/RST 的 TCP 反射噪音）
          5. 命中会话 dport 分散（≥ 5 个不同端口）
        """
        HTTP_SPORTS = {80, 8080, 8000, 8888}
        HTTP_ERROR_PREFIXES = (
            b'HTTP/1.0 4', b'HTTP/1.1 4', b'HTTP/2 4',
            b'HTTP/1.0 5', b'HTTP/1.1 5', b'HTTP/2 5',
        )

        # 按 dstIP → (srcIP, dport) 会话分组
        by_dst_session = collections.defaultdict(
            lambda: collections.defaultdict(list))
        for p in parsed:
            if p['proto'] != 6 or not p['tcp']:
                continue
            if p['sport'] not in HTTP_SPORTS:
                continue
            sess_key = (p['src_ip'], p['dport'])
            by_dst_session[p['dst_ip']][sess_key].append(p)

        for dst_ip, sessions in by_dst_session.items():
            # 筛选含 4xx/5xx 的会话（必要条件）
            hit_sessions = {
                k: pkts for k, pkts in sessions.items()
                if any(
                    p['tcp']['PSH'] and p['tcp']['payload']
                    and any(p['tcp']['payload'].startswith(pf)
                            for pf in HTTP_ERROR_PREFIXES)
                    for p in pkts
                )
            }
            if not hit_sessions:
                continue
            # 命中会话的 dport 需分散（≥ 5 个）
            if len(hit_sessions) < 5:
                continue
            all_pkts = [p for pkts in hit_sessions.values() for p in pkts]
            self.save('Volumetric Attack/TCP/HTTP Reflection', dst_ip,
                      'HTTP-Reflection', all_pkts, verbose,
                      _c('min_pkts', 'default'))

    # ──────────────────────────────────────────────────────────────────────────
    # 三、TCP 连接类攻击
    # ──────────────────────────────────────────────────────────────────────────

    def classify_tcp_state(self, sessions, verbose):
        """TCP空连接 / L4CC / Sockstress，基于 srcIP 会话分析。
        注：TCP-Replay-payload 已剥离到独立的 classify_tcp_replay()，本函数不再处理。"""
        null_by_dst      = collections.defaultdict(list)
        l4cc_by_dst      = collections.defaultdict(list)
        l4cc_cwr_by_dst  = collections.defaultdict(list)
        l4cc_ece_by_dst  = collections.defaultdict(list)
        sockstress_by_dst= collections.defaultdict(list)

        # TCP NullSession：按 (srcIP, dstIP) 聚合，> min_sessions 个合规会话才写出
        # L4CC/Replay/Sockstress 属于高速/慢速特殊场景，单会话即可判定
        null_pkts_by_src_dst  = collections.defaultdict(list)
        null_count_by_src_dst = collections.defaultdict(int)

        for key, pkts in sessions.items():
            # 从双向会话中识别客户端和服务端
            client_ip, client_port, server_ip, server_port = _identify_client(pkts)
            dst_ip = server_ip   # 受害者/服务端 IP（被攻击目标）
            dport  = server_port

            # 全量（用于 SYN/SYN-ACK 检测）
            tl = [p['tcp'] for p in pkts]
            # 客户端方向（用于攻击特征分析，避免服务端响应干扰）
            c_pkts = [p for p in pkts if p['src_ip'] == client_ip]
            tl_c   = [p['tcp'] for p in c_pkts]

            has_syn    = any(t['SYN'] and not t['ACK'] for t in tl)
            has_synack = any(t['SYN'] and t['ACK'] for t in tl)
            if not has_syn and not has_synack:
                continue

            # 完整会话门控：必须有 FIN 或 RST，确保会话已正常/异常结束
            # 仅对双向或单向均无结束标志的片段流量过滤，避免截断流误分类
            if not any(p['tcp']['FIN'] or p['tcp']['RST'] for p in pkts):
                continue

            # 纯 ACK：客户端发出的（即从 client_ip 来的）无 payload ACK 包
            pure_ack = sum(1 for p in pkts
                           if p['src_ip'] == client_ip
                           and p['tcp']['ACK'] and not p['tcp']['SYN']
                           and not p['tcp']['PSH'] and not p['tcp']['FIN']
                           and not p['tcp']['RST']
                           and len(p['tcp']['payload']) == 0)
            psh_ack     = sum(1 for p in pkts if p['src_ip']==client_ip
                              and p['tcp']['PSH'] and p['tcp']['ACK']
                              and not p['tcp']['CWR'] and not p['tcp']['ECE'])
            psh_ack_cwr = sum(1 for p in pkts if p['src_ip']==client_ip
                              and p['tcp']['PSH'] and p['tcp']['ACK'] and p['tcp']['CWR'])
            psh_ack_ece = sum(1 for p in pkts if p['src_ip']==client_ip
                              and p['tcp']['PSH'] and p['tcp']['ACK'] and p['tcp']['ECE'])
            has_psh  = any(p['tcp']['PSH'] for p in pkts if p['src_ip']==client_ip)
            has_end  = any(p['tcp']['FIN'] or p['tcp']['RST'] for p in pkts)

            # Sockstress 与 SlowRead 区分（参考 extract_slowattack.py）：
            # 两者都有零/小窗口行为，区别在于客户端 payload 总量：
            #   - Sockstress：建连后几乎不发应用层数据（payload_bytes < 50）
            #                 纯粹靠 win=0 耗尽服务端连接资源
            #   - SlowRead：发送了完整 HTTP/TLS 请求，只是收数据时故意小窗口
            #
            # 检测客户端的窗口滥用特征（零窗口 ≥3 次 或 小窗口 ≥8 次）
            # 只统计客户端发出的 ACK 包的窗口大小
            wscale_ss = 0
            for p in pkts:
                t = p['tcp']
                if t['SYN'] and not t['ACK'] and t['options'] and p['src_ip'] == client_ip:
                    wscale_ss = parse_tcp_wscale(t['options'])
                    break
            win_multiplier_ss = 1 << wscale_ss
            _ss_wins = [
                p['tcp']['win_size'] * win_multiplier_ss
                for p in pkts
                if p['src_ip'] == client_ip
                and p['tcp']['ACK'] and not p['tcp']['SYN'] and not p['tcp']['RST']
            ]
            _ss_zero_wins  = [c for c in _ss_wins if c == 0]
            _ss_small_wins = [c for c in _ss_wins if 0 < c <= _c('slow_attack','small_win_max')]
            _ss_behavior   = (len(_ss_zero_wins) >= _c('slow_attack','zero_win_min') or len(_ss_small_wins) >= _c('slow_attack','small_win_min'))
            _ss_duration   = (pkts[-1]['ts'] - pkts[0]['ts']
                              if len(pkts) >= 2 else 0)
            is_window_abuse = _ss_behavior and _ss_duration >= _c('slow_attack','duration_min')

            if is_window_abuse:
                # 统计客户端 payload 总字节数（不含 SYN/RST 包）
                client_tl = [p['tcp'] for p in pkts if p['src_ip'] == client_ip]
                total_payload_bytes = sum(
                    len(t['payload']) for t in client_tl
                    if t['payload'] and not t['SYN'] and not t['RST']
                )
                # 用分段重组识别 TLS ClientHello 和 HTTP Method（只重组客户端包）
                reassembled_ss, _ = reassemble_tcp_payload(client_tl)
                has_tls_ss = (
                    has_tls_client_hello(reassembled_ss) if reassembled_ss else False
                ) or any(
                    t['payload'] and len(t['payload']) >= 3
                    and t['payload'][0] in (0x14, 0x15, 0x16, 0x17)
                    and t['payload'][1] == 0x03
                    for t in client_tl if t['payload']
                )
                has_http_ss = bool(extract_http_methods(reassembled_ss)) if reassembled_ss else False

                # 核心分流：payload 极小（<50B）且无 HTTP/TLS 内容 → Sockstress
                SOCKSTRESS_MAX_PAYLOAD = 50
                if total_payload_bytes < SOCKSTRESS_MAX_PAYLOAD and not has_tls_ss and not has_http_ss:
                    sockstress_by_dst[dst_ip].extend(pkts)
                # SlowRead 的 win=0 场景保留给 classify_http / classify_https 处理

            # 注：TCP-Replay-payload 已剥离到独立分类器 classify_tcp_replay()，
            # 因为本函数有 SYN+FIN/RST 完整会话门控，无法处理 TCP-Replay 所需的
            # "无 SYN 会话"，且原规则会把 HTTPS 应用层攻击误判为 Replay。

            # HTTP/HTTPS 端口（80/443）的流量由应用层分类处理，跳过 L4CC/NullSession
            # 注意：仅排除 80 和 443，8080/8443 等非标准端口仍走 L4CC 判定
            if dport in (80, 443):
                continue

            # 排除含 HTTP/HTTPS 内容的会话（保留给应用层分类或其他分类器处理）
            # 只检查客户端发出的包，服务端响应不影响分类方向
            reassembled_l4, _ = reassemble_tcp_payload(tl_c)
            has_http_content = bool(extract_http_methods(reassembled_l4)) if reassembled_l4 else False
            has_tls_record = any(
                t['payload'] and len(t['payload']) >= 3
                and t['payload'][0] in (0x14, 0x15, 0x16, 0x17)
                and t['payload'][1] == 0x03
                for t in tl_c if t['payload']
            )
            has_client_hello = (
                has_tls_client_hello(reassembled_l4) if reassembled_l4 else False
            )
            if has_http_content or has_tls_record or has_client_hello:
                continue

            # TCP 空连接：无PSH，有纯ACK（>=3），有FIN/RST
            # 按 (srcIP, dstIP) 聚合；超过 min_sessions 个合规会话才写出（见循环后聚合）
            if not has_psh and pure_ack >= 3 and has_end:
                null_pkts_by_src_dst[(client_ip, dst_ip)].extend(pkts)
                null_count_by_src_dst[(client_ip, dst_ip)] += 1

            # L4CC：dport 不含 80/443，有 SYN，单会话纯ACK > 300
            # 无 HTTP/TLS 内容，排除应用层流量误归
            if has_syn and pure_ack > _c('tcp_state','null_session_pure_ack_min'):
                l4cc_by_dst[dst_ip].extend(pkts)

            # PSH-ACK-CWR L4CC
            if has_syn and psh_ack_cwr > _c('tcp_state','l4cc_psh_ack_min'):
                l4cc_cwr_by_dst[dst_ip].extend(pkts)

            # PSH-ACK-ECE L4CC
            if has_syn and psh_ack_ece > _c('tcp_state','l4cc_psh_ack_min'):
                l4cc_ece_by_dst[dst_ip].extend(pkts)

        # 注：TCP-Replay-payload 的跨会话匹配逻辑已剥离到 classify_tcp_replay()

        # TCP NullSession：只将 srcIP 超过 min_sessions 个合规会话的报文写出
        for (src_ip, dst_ip), count in null_count_by_src_dst.items():
            if count > _c('http', 'min_sessions'):
                null_by_dst[dst_ip].extend(null_pkts_by_src_dst[(src_ip, dst_ip)])
        for dst_ip, pkts in null_by_dst.items():
            self.save('TCP State Exhaustion Attack/NullSession', dst_ip,
                      'TCP-NullSession', pkts, verbose, _c('min_pkts','default'))
        for dst_ip, pkts in l4cc_by_dst.items():
            self.save('TCP State Exhaustion Attack/L4CC', dst_ip,
                      'L4CC', pkts, verbose, _c('min_pkts','default'))
        for dst_ip, pkts in l4cc_cwr_by_dst.items():
            self.save('TCP State Exhaustion Attack/L4CC', dst_ip,
                      'PSH-ACK-CWR', pkts, verbose, _c('min_pkts','default'))
        for dst_ip, pkts in l4cc_ece_by_dst.items():
            self.save('TCP State Exhaustion Attack/L4CC', dst_ip,
                      'PSH-ACK-ECE', pkts, verbose, _c('min_pkts','default'))
        for dst_ip, pkts in sockstress_by_dst.items():
            self.save('TCP State Exhaustion Attack/Sockstress', dst_ip,
                      'sockstress', pkts, verbose, _c('min_pkts','default'))

    def classify_tcp_replay(self, sessions, verbose):
        """TCP-Replay-payload：针对 TCP 私有协议（如游戏）的回放型攻击。

        典型特征：
          攻击者在不建立 TCP 握手的情况下，向受害者 TCP 端口直接注入大量
          带 payload 的 ACK 报文。多个攻击源（srcIP）同时回放同一段合法
          会话内容（来源通常是先前捕获或泄露的私有协议交互），以量取胜。

        识别条件（全部满足）：
          1. 整个会话完全无 SYN 与 SYN-ACK（任何方向）；攻击者无握手
          2. dport 不在 HTTP/HTTPS 端口（80/8080/443/8443，应用层攻击有专门分类器）
          3. 客户端方向 ACK+payload 报文数 ≥ replay_min_pkts（默认 10）
          4. ACK 序列号正常增长（符合 RFC）—— 区分于乱序/随机注入
             判据：seq 严格递增比例 ≥ replay_seq_growth_ratio（默认 0.8）
          5. 跨会话指纹匹配：同 (dst_ip, dport) 下相同 payload 前 64 字节指纹
             来自 ≥ replay_min_src_ips（默认 3）个不同 srcIP

        输出：Volumetric Attack/TCP/TCP Replay Attack/IPv4/<dst>_TCP-Replay-payload_<日期>.pcap
        """
        replay_candidates = collections.defaultdict(
            lambda: collections.defaultdict(list)
        )
        replay_by_dst = collections.defaultdict(list)
        min_pkts    = _c('tcp_state', 'replay_min_pkts',         default=10)
        min_src_ips = _c('tcp_state', 'replay_min_src_ips',      default=3)
        seq_grow    = _c('tcp_state', 'replay_seq_growth_ratio', default=0.8)

        for key, pkts in sessions.items():
            client_ip, _, server_ip, server_port = _identify_client(pkts)
            dst_ip = server_ip
            dport  = server_port

            # 条件1：会话无任何 SYN（含 SYN-ACK）
            if any(p['tcp']['SYN'] for p in pkts):
                continue
            # 条件2：dport 非 HTTP/HTTPS
            if dport in self.http_ports or dport in self.https_ports:
                continue

            # 客户端方向 ACK+payload 报文
            c_pkts = [p for p in pkts
                      if p['src_ip'] == client_ip
                      and p['tcp']['ACK']
                      and p['tcp']['payload']]
            # 条件3：报文数量门槛
            if len(c_pkts) < min_pkts:
                continue

            # 条件4：seq 正常增长（按发送顺序检查严格递增比例）
            seqs = [p['tcp']['seq_n'] for p in c_pkts]
            inc  = sum(1 for i in range(1, len(seqs)) if seqs[i] > seqs[i - 1])
            if inc / max(1, len(seqs) - 1) < seq_grow:
                continue

            # 条件5：收集候选，等跨会话匹配
            fp = c_pkts[0]['tcp']['payload'][:64]
            replay_candidates[(dst_ip, dport)][fp].append((client_ip, pkts))

        # 跨会话匹配：同指纹 ≥ min_src_ips 个不同 srcIP
        for (dst_ip, dport), fp_map in replay_candidates.items():
            for fp, sess_list in fp_map.items():
                src_ips = {s[0] for s in sess_list}
                if len(src_ips) >= min_src_ips:
                    for _, sess_pkts in sess_list:
                        replay_by_dst[dst_ip].extend(sess_pkts)

        for dst_ip, pkts in replay_by_dst.items():
            self.save('Volumetric Attack/TCP/TCP Replay Attack', dst_ip,
                      'TCP-Replay-payload', pkts, verbose, _c('min_pkts', 'default'))

    # ──────────────────────────────────────────────────────────────────────────
    # 四、HTTP 应用层攻击
    # ──────────────────────────────────────────────────────────────────────────

    def classify_http(self, sessions, verbose):
        # 按 (client_ip, server_ip) 聚合 HTTP 会话（双向 session 兼容）
        src_dst = collections.defaultdict(list)
        for key, pkts in sessions.items():
            client_ip, client_port, server_ip, server_port = _identify_client(pkts)
            if server_port not in self.http_ports:
                continue
            src_dst[(client_ip, server_ip)].append((client_port, server_port, pkts))

        cats = {k: collections.defaultdict(list) for k in (
            'Single-URL', 'GET_Flood', 'HEAD', 'POST', 'Other_Method',
            'RST-Session', 'Range-Amplification', 'HTTP-NullSession',
            'Multiple-Method', 'rootpath', 'DirectIP-Access',
            'SlowRead', 'SlowPost', 'SlowHeaders',
            'Abnormal-UA', 'BigResource-Access',
            'Multiple-URL', 'Abnormal-URL', 'Proxy-Access',
            'Random-URL',
            'HTTP-Parameter-Pollution', 'TCP-Segmentation-Evasion',
        )}
        # 行业目录：按 dstIP 归类，(subdir, suffix)
        # key = dst_ip, value = list of (subdir, suffix, pkts)
        industry_by_dst = collections.defaultdict(list)   # {dst_ip: [(subdir,suffix,pkts),...]}
        # 行业标记：先扫描所有 (src_ip, dst_ip) 对的所有 Host/URL，确认后才标记 dstIP
        # industry_tag：key=(src_ip,dst_ip)，value=行业标签
        # 精确到 (srcIP,dstIP) 对，防止 IP 复用导致其他 srcIP 的流量误归
        industry_tag = {}  # (src_ip, dst_ip) -> 'Government'/'API'
        for (src_ip, dst_ip), sport_sessions in src_dst.items():
            all_hosts = set()
            all_urls_scan = set()
            for _, _, pkts in sport_sessions:
                # 只分析客户端方向（请求包含 Host/URL，响应不含）
                tl_scan = [p['tcp'] for p in pkts if p['src_ip'] == src_ip]
                reasm_scan, _ = reassemble_tcp_payload(tl_scan)
                if reasm_scan:
                    hi = parse_http_request(reasm_scan)
                    if hi['host']:
                        all_hosts.add(hi['host'].lower())
                    if hi['url']:
                        all_urls_scan.add(hi['url'].lower())
                for t in tl_scan:
                    if t['payload']:
                        hi = parse_http_request(t['payload'])
                        if hi['host']:
                            all_hosts.add(hi['host'].lower())
                        if hi['url']:
                            all_urls_scan.add(hi['url'].lower())
            if all_hosts and any('gov' in h for h in all_hosts):
                industry_tag[(src_ip, dst_ip)] = 'Government'
            elif any(u.startswith('/api') for u in all_urls_scan):
                industry_tag[(src_ip, dst_ip)] = 'API'
        total_sess_by_dst = collections.defaultdict(int)

        for (src_ip, dst_ip), sport_sessions in src_dst.items():
            if self.wl.hit_http(src_ip, dst_ip):
                continue
            # 预计算：该 srcIP 到 dst_ip 的完整会话数（SYN + FIN/RST），
            # 用于 RST-Session / DirectIP / Abnormal-UA / Proxy / Abnormal-URL 等的 srcIP 级别门槛
            _n_src_complete = sum(
                1 for _, _, ps in sport_sessions
                if any(p['tcp']['SYN'] and not p['tcp']['ACK'] for p in ps)
                and any(p['tcp']['FIN'] or p['tcp']['RST'] for p in ps)
            )
            all_urls_for_single = []
            all_methods_urls    = []
            for _, _, pkts in sport_sessions:
                # 只分析客户端方向
                tl_pre = [p['tcp'] for p in pkts if p['src_ip'] == src_ip]
                reasm_pre, _ = reassemble_tcp_payload(tl_pre)
                seen_urls_this_sess = set()
                if reasm_pre:
                    # 用 extract_http_methods 从重组流提取所有方法（支持分段重组）
                    methods_reasm = extract_http_methods(reasm_pre)
                    hi_pre = parse_http_request(reasm_pre)
                    first_url = hi_pre['url'] if hi_pre['url'] else ''
                    first_host = hi_pre.get('host', '')
                    if first_url and not self.wl.hit_http(src_ip, dst_ip, first_host, first_url):
                        # 按重组识别的方法列表填充（每个方法对应第一个 URL，URL 精度次要）
                        for idx, m in enumerate(methods_reasm):
                            url_for_m = first_url if idx == 0 else first_url
                            all_urls_for_single.append(url_for_m)
                            all_methods_urls.append((m, url_for_m))
                            seen_urls_this_sess.add(url_for_m)
                    elif not methods_reasm and hi_pre['method'] and hi_pre['url']:
                        if not self.wl.hit_http(src_ip, dst_ip, first_host, first_url):
                            all_urls_for_single.append(first_url)
                            all_methods_urls.append((hi_pre['method'], first_url))
                            seen_urls_this_sess.add(first_url)
                for t in tl_pre:
                    if t['payload']:
                        hi = parse_http_request(t['payload'])
                        _HTTP_M = {'GET','POST','HEAD','PUT','DELETE','OPTIONS','PATCH','TRACE','CONNECT'}
                        if (hi['method'] and hi['url']
                                and hi['method'].rstrip(':').upper() in _HTTP_M
                                and hi['url'] not in seen_urls_this_sess):
                            if self.wl.hit_http(src_ip, dst_ip, hi.get('host',''), hi['url']):
                                continue
                            all_urls_for_single.append(hi['url'])
                            all_methods_urls.append((hi['method'], hi['url']))
                            seen_urls_this_sess.add(hi['url'])

            is_single_url   = bool(all_urls_for_single) and len(set(all_urls_for_single)) == 1
            # Multiple_URL：该 srcIP 跨所有会话请求了多个不同 URL
            is_multiple_url = len(set(all_urls_for_single)) > 1
            # srcIP 级别总请求数（用于各攻击类型最小次数限制）
            n_src_reqs = len(all_urls_for_single)

            # Browser_Emulation（收紧定义）：
            # 模拟浏览器行为的攻击工具会按固定流程运行：
            #   第1步：GET / （探路，必须是时序上第一个请求）
            #   第2步：解析响应，抓取静态资源/API/内页链接
            #   第3步：并发请求 JS/CSS/图片/API 等（URL池扩展）
            #
            # 判定条件（全部满足）：
            #   a. 跨所有会话按时间排序后，第一个 GET 请求必须是根目录 "/"
            #   b. 之后有 ≥2 个不同的非根目录 URL 请求
            #   c. 后续 URL 中包含静态资源特征（.js/.css/.png 等）
            #      OR 包含 /api/ 路径 OR 包含内页路径（含多层 /）
            #
            # 收紧理由：旧逻辑只要"有 GET / 且有其他 URL"即触发，误判率高

            # 按会话首包时间戳排序，重建时序 URL 列表
            def _session_first_ts(sess_tuple):
                _, _, sess_pkts = sess_tuple
                c_pkts_ts = [p for p in sess_pkts if p['src_ip'] == src_ip]
                return c_pkts_ts[0]['ts'] if c_pkts_ts else float('inf')

            sessions_ordered = sorted(sport_sessions, key=_session_first_ts)

            # 重建按时序排列的 (method, url, ts) 列表（仅含合法 HTTP Method）
            VALID_HTTP_METHODS = frozenset([
                'GET', 'POST', 'HEAD', 'PUT', 'DELETE',
                'OPTIONS', 'PATCH', 'CONNECT', 'TRACE',
            ])
            timed_requests = []
            for _, _, sess_pkts in sessions_ordered:
                tl_be = [p['tcp'] for p in sess_pkts if p['src_ip'] == src_ip]
                reasm_be, _ = reassemble_tcp_payload(tl_be)
                if reasm_be:
                    hi = parse_http_request(reasm_be)
                    if hi['method'] in VALID_HTTP_METHODS and hi['url']:
                        c_ts = next((p['ts'] for p in sess_pkts if p['src_ip'] == src_ip), 0)
                        timed_requests.append((hi['method'], hi['url'], c_ts))
                for t in tl_be:
                    if t['payload']:
                        hi = parse_http_request(t['payload'])
                        if hi['method'] in VALID_HTTP_METHODS and hi['url']:
                            # 避免与重组流重复
                            if not timed_requests or timed_requests[-1][1] != hi['url']:
                                c_ts = next((p['ts'] for p in sess_pkts
                                             if p['src_ip'] == src_ip and p['tcp']['payload']), 0)
                                timed_requests.append((hi['method'], hi['url'], c_ts))

            # 静态资源后缀集合
            STATIC_EXTS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
                           '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
                           '.webp', '.map', '.json'}

            def _is_static(url):
                path = url.split('?')[0].lower()
                return any(path.endswith(ext) for ext in STATIC_EXTS)

            def _is_api_or_page(url):
                # 去掉协议前缀后再计算路径深度，避免 http:// 中的斜杠误判
                path = url
                if '://' in url:
                    path = url.split('://', 1)[1]
                    # 再去掉 host 部分，只保留 path
                    path = path.split('/', 1)[1] if '/' in path else ''
                return '/api/' in path.lower() or path.count('/') >= 1

            is_browser_emulation = False
            if len(timed_requests) >= _c('http','browser_emulation_min_reqs'):
                first_method, first_url, _ = timed_requests[0]
                # 条件 a：第一个请求必须是 GET /（根目录）
                if first_method == 'GET' and first_url in ('/', ''):
                    # 条件 b：后续有 ≥2 个不同的非根目录 URL
                    # 排除根目录重复请求和绝对 URL 形式的根目录
                    subsequent_urls = [
                        u for _, u, _ in timed_requests[1:]
                        if u not in ('/', '') and not u.rstrip('/').endswith(':80') and
                           not u.rstrip('/').endswith(':443')
                    ]
                    unique_subsequent = set(subsequent_urls)
                    if len(unique_subsequent) >= _c('http','browser_emulation_min_sub'):
                        # 条件 c：后续 URL 中含静态资源 或 API/内页路径
                        has_static = any(_is_static(u) for u in unique_subsequent)
                        has_deep   = any(_is_api_or_page(u) for u in unique_subsequent)
                        if has_static or has_deep:
                            is_browser_emulation = True

            # Random_URL：URL 参数名包含随机字符串（混合大小写+数字，长度>=6）
            # 正常业务参数名通常全小写或下划线，攻击工具生成的参数名是乱码
            def _has_random_param_name(url):
                if '?' not in url: return False
                query = url.split('?', 1)[1]
                for param in query.split('&'):
                    name = param.split('=')[0] if '=' in param else param
                    if (len(name) >= 6 and
                            re.search(r'[A-Z]', name) and
                            re.search(r'[a-z]', name) and
                            re.search(r'[0-9]', name)):
                        return True
                return False

            n_reqs = len(all_urls_for_single)
            random_param_count = sum(1 for u in all_urls_for_single if _has_random_param_name(u))
            is_random_url = (
                n_reqs >= 5 and
                random_param_count > n_reqs * _c('http','random_url_random_ratio')  # 超过50%的请求含随机参数名
            )

            for sport, dport, pkts in sport_sessions:
                # 识别客户端（发 SYN 的一侧）
                c_ip, c_port, s_ip, s_port = _identify_client(pkts)
                # 客户端发出的包（用于 Method/URL/SlowRead 等分析）
                c_pkts = [p for p in pkts if p['src_ip'] == c_ip]
                tl     = [p['tcp'] for p in c_pkts]   # 只重组客户端方向

                has_syn      = any(t['SYN'] and not t['ACK'] for t in [p['tcp'] for p in pkts])
                has_synack   = any(t['SYN'] and t['ACK']      for t in [p['tcp'] for p in pkts])
                # 严格门控：必须有 SYN（客户端发起建连）才处理
                # 确保攻击样本分类基于完整会话，避免半段流量误判
                if not has_syn and not has_synack:
                    continue
                # 完整会话门控：必须有 FIN 或 RST 表示会话已结束
                # Government / API 继承此门控（同一循环内处理）
                if not any(p['tcp']['FIN'] or p['tcp']['RST'] for p in pkts):
                    continue

                # Window Scale 从客户端 SYN 提取
                wscale = 0
                for t in tl:
                    if t['SYN'] and not t['ACK'] and t['options']:
                        wscale = parse_tcp_wscale(t['options'])
                        break
                win_multiplier = 1 << wscale

                pure_ack = sum(1 for t in tl
                               if t['ACK'] and not t['SYN']
                               and not t['PSH'] and not t['FIN'] and not t['RST']
                               and len(t['payload']) == 0)

                sess_methods   = []
                per_pkt_multi  = False
                has_range      = False
                ends_rst       = any(t['RST'] for t in tl)
                has_slow_read  = False
                has_slow_post  = False
                has_slow_headers = False
                big_resource   = False
                hosts_seen     = set()
                urls_seen      = set()
                ua_seen        = ''
                has_method     = False
                has_proxy      = False

                # ACK 序列号增长（大资源判断）
                ack_vals = sorted(
                    t['ack_n'] for t in tl
                    if t['ACK'] and not t['SYN'] and len(t['payload']) == 0)
                ack_growth = 0
                for i in range(1, len(ack_vals)):
                    diff = ack_vals[i] - ack_vals[i-1]
                    if 0 < diff < 2**31:
                        ack_growth += diff

                # ── TCP 分段重组：先重组再解析，解决分段导致Method漏识别 ──────
                reassembled, ack_segmented = reassemble_tcp_payload(tl)

                # Slow Read：零/小窗口行为 + 会话持续时间验证（抗误报）
                # 对齐参考脚本：不要求零窗口前必须出现过正常窗口
                # （攻击工具 SYN 之后立刻发零窗口，ACK 序列里无正常窗口）
                _sr_wins = [
                    t['win_size'] * win_multiplier
                    for t in tl if t['ACK'] and not t['SYN'] and not t['RST']
                ]
                _sr_zero_wins = [c for c in _sr_wins if c == 0]
                _sr_small_wins = [c for c in _sr_wins if 0 < c <= _c('slow_attack','small_win_max')]
                _sr_behavior = (len(_sr_zero_wins) >= _c('slow_attack','zero_win_min') or len(_sr_small_wins) >= _c('slow_attack','small_win_min'))
                _sr_duration = pkts[-1]['ts'] - pkts[0]['ts'] if len(pkts) >= 2 else 0
                if _sr_behavior and _sr_duration >= _c('slow_attack','duration_min'):
                    has_slow_read = True

                # 逐包收集 header 元数据（Range/Proxy/Host/URL/UA），不提取 Method
                # 注意：parse_http_request 对延续包（continuation packet）的首行可能误把
                #       Referer:/Cookie: 等头当成 method，提取出 Referer URL 加入 urls_seen，
                #       导致 HTTP Parameter Pollution 误触发。
                #       修复：只有当 method 是合法 HTTP 方法时，才将 url 加入 urls_seen。
                _HTTP_METHODS = {'GET', 'POST', 'HEAD', 'PUT', 'DELETE',
                                 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'}
                for t in tl:
                    if t['payload']:
                        hi = parse_http_request(t['payload'])
                        if not has_range and hi['has_range']:
                            has_range = True
                        if not has_proxy and hi['has_proxy']:
                            has_proxy = True
                        if hi['host']:
                            hosts_seen.add(hi['host'])
                        if hi['url'] and hi['method'].rstrip(':').upper() in _HTTP_METHODS:
                            urls_seen.add(hi['url'])
                        if hi['ua'] and not ua_seen:
                            ua_seen = hi['ua']

                # ── 从重组流提取 Method（主要路径）──────────────────────────
                if reassembled:
                    hi_reasm = parse_http_request(reassembled)
                    pkt_methods_reasm = extract_http_methods(reassembled)
                    sess_methods.extend(pkt_methods_reasm)
                    if not has_range and hi_reasm['has_range']:
                        has_range = True
                    if not has_proxy and hi_reasm['has_proxy']:
                        has_proxy = True
                    if hi_reasm['host']:
                        hosts_seen.add(hi_reasm['host'])
                    if hi_reasm['url'] and hi_reasm['method'].rstrip(':').upper() in _HTTP_METHODS:
                        urls_seen.add(hi_reasm['url'])
                    if hi_reasm['ua'] and not ua_seen:
                        ua_seen = hi_reasm['ua']

                # Multiple-Method（HTTP Pipeline 攻击）：
                # 定义：单个 PSH 报文的 payload 内，包含 ≥2 个完整的 HTTP 请求。
                # 攻击工具将多个 HTTP 请求塞入一个 TCP 分段，绕过 WAF 单请求检测。
                # 判定：逐包扫描，只要有一个 PSH 包内出现 ≥2 个 Method 行即触发。
                # 注意：不要求不同 Method 类型，GET+GET 也是 Pipeline 攻击。
                import re as _re
                HTTP_METHOD_RE = _re.compile(
                    rb'(?:^|\r\n)(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) '
                )
                for t in tl:
                    if t['PSH'] and t['payload'] and len(t['payload']) > _c('http','multiple_method_min_pkt_len'):
                        methods_in_pkt = HTTP_METHOD_RE.findall(t['payload'])
                        if len(methods_in_pkt) >= 2:
                            per_pkt_multi = True
                            break

                # 重组后仍无 Method：取前10个有 payload 的包重组再尝试识别
                # 若仍无 Method 则归空连接（ACK数量 > 300）
                if not sess_methods:
                    # 前10个有 payload 的包（不限 PSH，排除 RST/FIN）
                    top10_pkts = [t for t in tl
                                  if t['payload'] and not t['RST'] and not t['FIN']][:10]
                    if top10_pkts:
                        top10_reasm, _ = reassemble_tcp_payload(top10_pkts)
                        top10_methods = extract_http_methods(top10_reasm)
                        sess_methods.extend(top10_methods)
                        if not sess_methods:
                            hi_top = parse_http_request(top10_reasm)
                            if hi_top['host']:
                                hosts_seen.add(hi_top['host'])
                            if hi_top['url']:
                                urls_seen.add(hi_top['url'])
                    if not sess_methods:
                        # 无法识别 Method，但有 SlowRead 特征（如加密/不完整请求）
                        # 只要会话有 SYN，窗口滥用+持续时间足够就归 SlowRead
                        if has_slow_read:
                            total_sess_by_dst[dst_ip] += 1
                            cats['SlowRead'][dst_ip].extend(pkts)
                        # 前10包重组后仍无 Method，也无 SlowRead → HTTP-NullSession
                        elif dport in self.http_ports and pure_ack > _c('tcp_state','null_session_pure_ack_min'):
                            cats['HTTP-NullSession'][dst_ip].extend(pkts)
                        continue

                has_method = True
                method_set = set(sess_methods)

                # 白名单检查：需匹配任意一个 Host 或 URL 即命中
                # 逐个遍历 hosts_seen 和 urls_seen 全集，避免只取单个引起漏护
                if (any(self.wl.hit_http(src_ip, dst_ip, h, '') for h in hosts_seen)
                        or any(self.wl.hit_http(src_ip, dst_ip, '', u) for u in urls_seen)
                        or self.wl.hit_http(src_ip, dst_ip)):
                    continue

                # host / url：供 DirectIP_Access、Abnor_URL 等子分类使用
                host = next(iter(hosts_seen), '')
                url  = next(iter(urls_seen), '')

                # 大资源：ack 增长 > 50KB
                if ack_growth > _c('http','bigresource_ack_growth'):
                    big_resource = True

                def _add(cat):
                    cats[cat][dst_ip].extend(pkts)

                # 统计该 dst_ip 下的 HTTP 总会话数
                total_sess_by_dst[dst_ip] += 1

                # ── 各分类独立写出 ─────────────────────────────────────────
                if per_pkt_multi:   _add('Multiple-Method')  # 单包内多请求，报文内有强证据，1次即触发
                # Range-Amplification：srcIP 总请求 ≥ min_sessions 次（排除偶发 Range 头）
                if has_range and n_src_reqs >= _c('http', 'min_sessions'):
                    _add('Range-Amplification')
                # ── Slow POST（含 Tor's Hammer）────────────────────────────
                # 条件1：会话中出现 POST 请求
                # 条件2：找到首个 POST 包位置，之后的 PSH 包中
                #        小 payload（≤45字节）包数 ≥ 5
                if 'POST' in method_set:
                    post_idx = next(
                        (i for i, t in enumerate(tl)
                         if t['payload'] and b'POST' in t['payload'][:10]), None
                    )
                    if post_idx is not None:
                        after_post_psh = [
                            t['payload'] for t in tl[post_idx + 1:]
                            if t['PSH'] and t['payload']
                        ]
                        # 所有后续 PSH 包均 ≤45 字节，且数量 ≥ 5
                        if (len(after_post_psh) >= _c('http','slow_post_psh_min')
                                and all(1 <= len(pl) <= _c('http','slow_post_psh_max_len') for pl in after_post_psh)):
                            has_slow_post = True

                # ── SlowHeaders（Slowloris）──────────────────────────────────
                # 条件1：会话中出现 GET 或 HEAD 请求
                # 条件2：找到首个 GET/HEAD 包位置，之后的 PSH 包中
                #        小 payload（≤45字节）包数 ≥ 3
                if method_set & {'GET', 'HEAD'}:
                    gh_idx = next(
                        (i for i, t in enumerate(tl)
                         if t['payload'] and
                            (b'GET ' in t['payload'][:10] or b'HEAD ' in t['payload'][:10])),
                        None
                    )
                    if gh_idx is not None:
                        after_gh_psh = [
                            t['payload'] for t in tl[gh_idx + 1:]
                            if t['PSH'] and t['payload']
                        ]
                        # 所有后续 PSH 包均 ≤45 字节，且数量 ≥ 3
                        if (len(after_gh_psh) >= _c('http','slow_headers_psh_min')
                                and all(1 <= len(pl) <= _c('http','slow_headers_psh_max_len') for pl in after_gh_psh)):
                            has_slow_headers = True

                # RST-Session：srcIP 需有 > min_sessions 个完整会话（避免单次偶发RST误判）
                if ends_rst and _n_src_complete > _c('http', 'min_sessions'):
                    _add('RST-Session')
                if has_slow_read:      _add('SlowRead')         # 慢速攻击，单会话即可
                if has_slow_post:      _add('SlowPost')         # 慢速攻击，单会话即可
                if has_slow_headers:   _add('SlowHeaders')      # 慢速攻击，单会话即可

                if big_resource and n_src_reqs >= _c('http','bigresource_min_reqs'):   _add('BigResource-Access')  # ≥10次
                # Proxy-Access：srcIP 需有 > min_sessions 个完整会话
                if has_proxy and _n_src_complete > _c('http', 'min_sessions'):
                    _add('Proxy-Access')

                # GET / HEAD / POST Flood 均改为 srcIP 级别统计，在外层循环中判断（见下方）
                # Other Method Flood：other_method_min_reqs 已调整为 5
                if method_set & {m.decode() for m in UNCOMMON_METHODS} and n_src_reqs >= _c('http','other_method_min_reqs'):
                    _add('Other_Method')

                # Single URL：srcIP 对同一 URL 请求次数 > single_url_min_reqs (5)
                if is_single_url and n_src_reqs > _c('http','single_url_min_reqs'):   _add('Single-URL')

                # rootpath：srcIP 总请求 ≥ min_sessions 次（排除偶发根路径访问）
                if all_urls_for_single and set(all_urls_for_single) == {'/'} and n_src_reqs >= _c('http', 'min_sessions'):
                    _add('rootpath')

                # DirectIP-Access：srcIP 需有 > min_sessions 个完整会话（1次可能是正常CDN行为）
                if host and is_ip_address(host) and _n_src_complete > _c('http', 'min_sessions'):
                    _add('DirectIP-Access')

                # Abnormal-UA：srcIP 需有 > min_sessions 个完整会话（单次可能是工具误配）
                if is_abnormal_ua(ua_seen) and _n_src_complete > _c('http', 'min_sessions'):
                    _add('Abnormal-UA')

                # Multiple_URL：≥10次
                if is_multiple_url and n_src_reqs >= _c('http','multiple_url_min_reqs'):    _add('Multiple-URL')

                # Browser_Emulation：需 ≥3 次请求（根目录+后续≥2个URL）才触发
                # 注意：Browser-Emulation 是跨会话判定，写出逻辑在外层 (src_ip,dst_ip)
                # 循环结束后统一处理（见下方 be_write_queue），此处不重复写出

                # Random_URL：已由 n_reqs>=5 控制，保持不变
                if is_random_url:                   _add('Random-URL')

                # ── Abnormal URL 子分类（互斥优先级，一个会话只归一类）────────
                # 优先级：TCP Segmentation Evasion > HTTP Parameter Pollution > Abnormal-URL
                #
                # 1. TCP Segmentation Evasion：单个 HTTP 请求的方法/头部被切成 ≥10 个极小 TCP 段
                #    严格定义：以请求边界（Method 起始包）拆分，逐请求统计 <100B 小分段数
                #    只要有任意一个请求的小分段数 ≥ tcp_seg_evasion_min，即认定为分段逃逸攻击
                #    排除 TCP Keep-Alive 包：payload=1字节\x00（或任意1字节且非PSH），
                #    Keep-Alive 是正常连接保活机制，不是分段逃逸
                HTTP_METHOD_PREFIXES = (b'GET ', b'POST', b'HEAD', b'PUT ', b'DELE',
                                        b'OPTI', b'PATC', b'TRAC', b'CONN')
                _payload_segs = [t for t in tl
                                 if t['payload'] and not t['SYN'] and not t['RST']
                                 and not (len(t['payload']) == 1 and not t['PSH'])]  # 排除 Keep-Alive
                # 按 Method 起始包切割请求边界
                _req_start_indices = [i for i, t in enumerate(_payload_segs)
                                      if t['payload'][:4] in HTTP_METHOD_PREFIXES
                                      or t['payload'][:3] in (b'GET', b'PUT')]
                _is_seg_evasion = False
                if _req_start_indices:
                    _req_start_indices.append(len(_payload_segs))  # 哨兵
                    for _ri in range(len(_req_start_indices) - 1):
                        _req_segs = _payload_segs[_req_start_indices[_ri]:_req_start_indices[_ri + 1]]
                        _small = sum(1 for t in _req_segs if len(t['payload']) < 100)
                        if _small >= _c('http', 'tcp_seg_evasion_min'):
                            _is_seg_evasion = True
                            break
                if _is_seg_evasion:
                    _add('TCP-Segmentation-Evasion')

                # 2. HTTP Parameter Pollution：查询字符串超长 + 真正的污染特征
                #    仅靠长度判断会误杀含 URL 编码中文/URL 的正常请求（如搜索追踪 API）
                #    需同时满足：(a) query 超长 AND (b) 至少一项 HPP 结构特征：
                #      - 重复参数名（id=1&id=2，最强特征）
                #      - 参数值中含编码注入（%26=%3D，在值中注入分隔符）
                #      - 参数数量异常多（≥15个不同参数名，且 query 超长）
                elif any(
                    _is_param_pollution(u, _c('http', 'param_pollution_query_len'))
                    for u in urls_seen
                ):
                    _add('HTTP-Parameter-Pollution')

                # 3. Abnormal URL（通用乱码）：URL 含大量非打印/高字节字符（排除中文）
                #    仅在未触发上述两类时才判断；srcIP 需有 > min_sessions 个完整会话
                elif (any(has_garbled_url(u) for u in urls_seen)
                        and _n_src_complete > _c('http', 'min_sessions')):
                    _add('Abnormal-URL')

            # Browser-Emulation 是跨会话判定：汇集该 (src_ip, dst_ip) 所有会话的包统一写出
            # 不在单会话内层循环写出，避免同一攻击行为被分成多个小文件
            # 注意：不经过 total_sess_by_dst 门槛（BE 本身由 n_src_reqs>=3 控制），直接 save
            if is_browser_emulation and n_src_reqs >= _c('http','browser_emulation_min_reqs'):
                all_be_pkts = []
                for _, _, sess_pkts in sport_sessions:
                    all_be_pkts.extend(sess_pkts)
                if all_be_pkts:
                    self.save('Application Attack/HTTP/Browser Emulation',
                              dst_ip, 'Browser-Emulation', all_be_pkts, verbose)

            # GET / HEAD / POST Flood（srcIP 级别统一判定）：
            # 定义：该 srcIP 对该 dstIP 的 HTTP 请求总次数 > 10，
            #       且目标方法（GET/HEAD/POST）占比 ≥ 80%
            # 跨所有会话汇总方法列表，all_methods_urls 已含分段重组识别的方法
            _all_methods = [m.upper() for m, _ in all_methods_urls]
            _total_reqs  = len(_all_methods)
            if _total_reqs > 10:
                # 填充 cats 而非直接 save，确保后续行业双写（Government/API）能正常覆盖
                _all_sess_pkts = []
                for _, _, _sp in sport_sessions:
                    _all_sess_pkts.extend(_sp)
                if _all_sess_pkts:
                    for _method_name, _cat_key in [('GET', 'GET_Flood'), ('HEAD', 'HEAD'), ('POST', 'POST')]:
                        if _all_methods.count(_method_name) / _total_reqs >= 0.8:
                            cats[_cat_key][dst_ip].extend(_all_sess_pkts)

        dir_map = {
            'Single-URL':          ('Application Attack/HTTP/Single URL',              'Single-URL'),
            'GET_Flood':           ('Application Attack/HTTP/GET Flood',            'GET-Flood'),
            'HEAD':                ('Application Attack/HTTP/HEAD Flood',           'HEAD-Flood'),
            'POST':                ('Application Attack/HTTP/POST Flood',           'POST-Flood'),
            'Other_Method':        ('Application Attack/HTTP/Other Method',         'Other-Method-Flood'),
            'RST-Session':         ('Application Attack/HTTP/RST Session',          'RST-Session'),
            'Range-Amplification': ('Application Attack/HTTP/Range Amplification',  'Range-Amplification'),
            'HTTP-NullSession':    ('Application Attack/HTTP/HTTP NullSession',     'HTTP-NullSession'),
            'Multiple-Method':     ('Application Attack/HTTP/Multiple Method',      'Multiple-Method'),
            'rootpath':            ('Application Attack/HTTP/rootpath',             'rootpath'),
            'DirectIP-Access':     ('Application Attack/HTTP/DirectIP Access',      'DirectIP-Access'),
            'SlowRead':            ('Application Attack/HTTP/SlowAttack',           'SlowRead'),
            'SlowPost':            ('Application Attack/HTTP/SlowAttack',           'SlowPost'),
            'SlowHeaders':         ('Application Attack/HTTP/SlowAttack',           'SlowHeaders'),
            'Abnormal-UA':         ('Application Attack/HTTP/Abnormal UA',          'Abnormal-UA'),
            'BigResource-Access':  ('Application Attack/HTTP/BigResource Access',   'BigResource-Access'),
            'Multiple-URL':        ('Application Attack/HTTP/Multiple URL',         'Multiple-URL'),
            'Abnormal-URL':        ('Application Attack/HTTP/Abnormal URL',          'Abnormal-URL'),
            'Proxy-Access':        ('Application Attack/HTTP/Proxy Access',         'Proxy-Access'),
            'Random-URL':          ('Application Attack/HTTP/Random URL',           'Random-URL'),
            'HTTP-Parameter-Pollution': ('Application Attack/HTTP/Abnormal URL',   'HTTP-Parameter-Pollution'),
            'TCP-Segmentation-Evasion': ('Application Attack/HTTP/Abnormal URL',   'TCP-Segmentation-Evasion'),
        }

        # 正常归类
        # TCP-Segmentation-Evasion 和 HTTP-Parameter-Pollution 是单会话级特征，
        # 不受 total_sess_by_dst 门槛限制（1个会话就足以确认攻击特征）
        no_session_threshold = {'TCP-Segmentation-Evasion', 'HTTP-Parameter-Pollution'}
        for cat, (subdir, suffix) in dir_map.items():
            for dst_ip, pkts in cats[cat].items():
                if cat in no_session_threshold or total_sess_by_dst[dst_ip] >= _c('http','min_sessions'):
                    self.save(subdir, dst_ip, suffix, pkts, verbose)

        # 行业双写：按 dstIP 聚合所有 gov srcIP 的包后一次性 save
        gov_src_by_dst = collections.defaultdict(dict)  # dst_ip -> {src_ip: ind}
        for (src_ip, dst_ip), ind in industry_tag.items():
            gov_src_by_dst[dst_ip][src_ip] = ind

        for dst_ip, src_ind_map in gov_src_by_dst.items():
            if total_sess_by_dst[dst_ip] < _c('http','min_sessions'):
                continue
            # 取行业标签（同一 dstIP 下优先 Government，其次 API）
            ind = next(v for v in src_ind_map.values())
            gov_srcs = set(src_ind_map.keys())
            for cat, (subdir, suffix) in dir_map.items():
                all_pkts = cats[cat].get(dst_ip, [])
                if not all_pkts:
                    continue
                # 合并所有 gov srcIP 的包
                src_pkts = [p for p in all_pkts if p['src_ip'] in gov_srcs]
                if not src_pkts:
                    continue
                ind_subdir = subdir.replace('Application Attack/HTTP',
                                            f'Application Attack/{ind}/HTTP')
                self.save(ind_subdir, dst_ip, suffix, src_pkts, verbose)

    # ──────────────────────────────────────────────────────────────────────────
    # 五、HTTPS 应用层攻击
    # ──────────────────────────────────────────────────────────────────────────

    def classify_https(self, sessions, verbose):
        src_dst = collections.defaultdict(list)
        for key, pkts in sessions.items():
            client_ip, client_port, server_ip, server_port = _identify_client(pkts)
            if server_port not in self.https_ports:
                continue
            src_dst[(client_ip, server_ip)].append((client_port, server_port, pkts))

        cats = {k: collections.defaultdict(list) for k in (
            'HTTPS-NullSession', 'Client-Hello-Flood', 'Client-Hello-FIN-Flood',
            'Negotiation-Abuse',
            'plaintext-access', 'Abnormal-SNI', 'Same-Request-PktLen',
            'RST-Session', 'SlowRead', 'BigResource-Access',
            'MultipleAD-perPacket', 'CC', 'Suspicious-HTTP2', 'THC_SSL',
            'HTTP2-Rapid-Reset',
        )}
        # 按 dst_ip 统计 HTTPS 总会话数（用于最小会话数门槛）
        total_sess_by_dst = collections.defaultdict(int)

        # ── JA4 聚合（C+D+A 三合一）────────────────────────────────────────
        # 结构：ja4_aggr[(dst_ip, ja4)] = {'srcs': set, 'pkts': list, 'sessions': int}
        # 用途：
        #   C 自聚类（JA4-Botnet）：同 JA4 → 同 dst 出现 ≥ N 个不同 srcIP
        #   A 黑名单（JA4-Malicious）：JA4 命中 self.ja4_blacklist 即归类
        #   D 元数据日志：所有命中归类的会话其 JA4 写入 verbose 输出便于沉淀指纹
        ja4_aggr = collections.defaultdict(lambda: {
            'srcs': set(), 'pkts': [], 'sessions': 0,
        })
        # 已命中黑名单的 (dst_ip, ja4) 在主循环里直接写出
        ja4_malicious_pkts = collections.defaultdict(list)   # (dst_ip, matched_pattern) → pkts
        # JA4 元数据摘要（D 沉淀指纹用）
        ja4_observed       = collections.defaultdict(int)    # ja4 → session_count

        def _scan_tls_records(pl):
            """扫描整个 payload 中所有 TLS records，返回 content_type list
            对于 record body 分段的情况（rec_len > 实际剩余），仍记录 content_type"""
            types = []
            pos = 0
            while pos + 5 <= len(pl):
                ct      = pl[pos]
                ver_maj = pl[pos+1]
                if ver_maj != 0x03:
                    break
                if ct not in (0x14, 0x15, 0x16, 0x17):
                    break
                rec_len = struct.unpack('>H', pl[pos+3:pos+5])[0]
                if rec_len > _c('https','tls_max_record_len'):
                    break
                types.append(ct)
                if pos + 5 + rec_len > len(pl):
                    # record body 分段：header 完整但 body 不完整，记录类型后停止
                    break
                pos += 5 + rec_len
            return types

        for (src_ip, dst_ip), sport_sessions in src_dst.items():
            # Same-Request-PktLen 组级统计（跨该 (srcIP, dstIP) 所有会话累加）
            grp_app_data_lens = []   # 所有会话中客户端 AppData 的 TLS rlen
            grp_all_pkts      = []   # 含 AppData 会话的全量报文（用于写出）

            # 预计算：该 srcIP 到 dst_ip 的完整会话数（SYN + FIN/RST）
            # 用于 Client-Hello-Flood / Negotiation-Abuse / THC-SSL /
            # plaintext-access / Abnormal-SNI / RST-Session /
            # MultipleAD-perPacket / Suspicious-HTTP2 的 srcIP 级别门槛
            _n_src_complete = sum(
                1 for _, _, ps in sport_sessions
                if any(p['tcp']['SYN'] and not p['tcp']['ACK'] for p in ps)
                and any(p['tcp']['FIN'] or p['tcp']['RST'] for p in ps)
            )

            for sport, dport, pkts in sport_sessions:
                # 全量（用于 SYN 检测）；客户端方向（用于 TLS/SlowRead 分析）
                tl_all = [p['tcp'] for p in pkts]
                c_pkts = [p for p in pkts if p['src_ip'] == src_ip]
                tl     = [p['tcp'] for p in c_pkts]   # 客户端方向
                # 严格门控：必须有 SYN（客户端发起建连）才处理
                has_syn = any(t['SYN'] and not t['ACK'] for t in tl_all)
                if not has_syn:
                    continue
                # 完整会话门控：必须有 FIN 或 RST 表示会话已结束
                # Government / API（HTTPS）继承此门控（同一循环内处理）
                if not any(t['FIN'] or t['RST'] for t in tl_all):
                    continue

                # 从客户端 SYN 包的 TCP Options 提取 Window Scale
                wscale = 0
                for t in tl:
                    if t['SYN'] and not t['ACK'] and t['options']:
                        wscale = parse_tcp_wscale(t['options'])
                        break
                win_multiplier = 1 << wscale

                # 计入 dst_ip 总会话数
                total_sess_by_dst[dst_ip] += 1

                # pure_ack：只统计客户端发出的纯 ACK（服务端 ACK 不计）
                pure_ack = sum(1 for t in tl
                               if t['ACK'] and not t['SYN']
                               and not t['PSH'] and not t['FIN'] and not t['RST']
                               and len(t['payload']) == 0)

                f_client_hello  = False
                f_hello_fin     = False   # ClientHello 与 FIN 在同一报文（攻击工具优化变种）
                f_change_cipher = False
                f_app_data      = False
                f_plaintext     = False
                sni             = ''
                alpn_protocols  = []
                client_hello_count = 0
                ccs_count          = 0
                ends_rst        = any(t['RST'] for t in tl)
                has_slow_read   = False
                app_data_lens   = []
                multi_ad_pkts   = []
                big_resource    = False

                ack_vals = sorted(
                    t['ack_n'] for t in tl
                    if t['ACK'] and not t['SYN'] and len(t['payload']) == 0)
                ack_growth = 0
                for i in range(1, len(ack_vals)):
                    diff = ack_vals[i] - ack_vals[i-1]
                    if 0 < diff < 2**31:
                        ack_growth += diff
                if ack_growth > _c('http','bigresource_ack_growth'):
                    big_resource = True

                # ── TCP 分段重组：先重组所有 payload，再做 TLS 解析 ──────────
                reassembled_https, _ = reassemble_tcp_payload(tl)

                # ── 计算 JA4 客户端指纹（C+D+A 三合一前置）──────────────────
                # 仅对 TLS ClientHello 计算；失败/非 TLS 返回空串
                sess_ja4 = compute_ja4(reassembled_https) if reassembled_https else ''
                if sess_ja4:
                    ja4_aggr[(dst_ip, sess_ja4)]['srcs'].add(src_ip)
                    ja4_aggr[(dst_ip, sess_ja4)]['pkts'].extend(pkts)
                    ja4_aggr[(dst_ip, sess_ja4)]['sessions'] += 1
                    ja4_observed[sess_ja4] += 1
                    # A 黑名单立即命中检测（不依赖会话数门槛）
                    _bl_hit = match_ja4_blacklist(sess_ja4, self.ja4_blacklist)
                    if _bl_hit:
                        ja4_malicious_pkts[(dst_ip, sess_ja4, _bl_hit)].extend(pkts)

                # Slow Read：零/小窗口行为 + 会话持续时间验证
                # 对齐参考脚本：不要求零窗口前必须出现过正常窗口
                _sr_wins = [
                    t['win_size'] * win_multiplier
                    for t in tl if t['ACK'] and not t['SYN'] and not t['RST']
                ]
                _sr_zero_wins  = [c for c in _sr_wins if c == 0]
                _sr_small_wins = [c for c in _sr_wins if 0 < c <= _c('slow_attack','small_win_max')]
                _sr_behavior   = (len(_sr_zero_wins) >= _c('slow_attack','zero_win_min') or len(_sr_small_wins) >= _c('slow_attack','small_win_min'))
                _sr_duration   = pkts[-1]['ts'] - pkts[0]['ts'] if len(pkts) >= 2 else 0
                if _sr_behavior and _sr_duration >= _c('slow_attack','duration_min'):
                    has_slow_read = True

                for t in tl:
                    if not t['payload']:
                        continue
                    pl = t['payload']
                    # 明文检测只看 PSH 包（ACK包不会是HTTP请求）
                    if t['PSH'] and not f_plaintext and is_plaintext_http(pl):
                        f_plaintext = True
                        continue

                    # TLS record 扫描：所有带 payload 的包都要扫
                    rec_types = _scan_tls_records(pl)
                    if not rec_types:
                        continue

                    for ct in rec_types:
                        if ct == 0x16 and has_tls_client_hello(pl):
                            client_hello_count += 1
                            if not f_client_hello:
                                f_client_hello = True
                                sni = extract_sni(pl)
                                alpn_protocols = extract_alpn(pl)
                                # Client-Hello-FIN-Flood 变种：ClientHello 与 FIN 同包
                                if t['FIN']:
                                    f_hello_fin = True
                        if ct == 0x14:
                            f_change_cipher = True
                            ccs_count += 1
                        if ct == 0x17:
                            f_app_data = True

                    if 0x17 in rec_types:
                        # 修复根因：使用 TLS record header 的 rlen 字段（实际记录长度），
                        # 而非 TCP payload 长度。
                        # 原因：大 TLS record 会被 TCP 分成多个 MSS 大小的段传输，每个段
                        # 都以 0x17 0x03 开头（TLS 记录头），_scan_tls_records 均能检测到。
                        # 旧代码 append(len(pl)) 导致 [MSS, MSS, MSS, ...] = 全部相同，误触发。
                        # 新代码从 TLS 头部读取实际 rlen（各记录大小不同），不会误触发。
                        _ap = 0
                        while _ap + 5 <= len(pl):
                            _ct = pl[_ap]; _v = pl[_ap + 1]
                            if _v != 0x03 or _ct not in (0x14, 0x15, 0x16, 0x17):
                                break
                            _rlen = struct.unpack_from('>H', pl, _ap + 3)[0]
                            if _rlen == 0 or _rlen > _c('https', 'tls_max_record_len'):
                                break
                            if _ct == 0x17:
                                app_data_lens.append(_rlen)
                            if _ap + 5 + _rlen > len(pl):
                                break   # record body 跨段，当前 TCP 段只含 header
                            _ap += 5 + _rlen
                        if rec_types.count(0x17) > 1:
                            multi_ad_pkts.extend(pkts)

                # 逐包未识别到 ClientHello 时，尝试从重组流解析（处理分段传输）
                if not f_client_hello and reassembled_https:
                    if has_tls_client_hello(reassembled_https):
                        f_client_hello = True
                        sni = extract_sni(reassembled_https)
                        alpn_protocols = extract_alpn(reassembled_https)
                        client_hello_count = max(client_hello_count, 1)
                    # 扫描重组流中 ChangeCipherSpec / AppData
                    reasm_rec_types = _scan_tls_records(reassembled_https)
                    if 0x14 in reasm_rec_types and not f_change_cipher:
                        f_change_cipher = True
                    if 0x17 in reasm_rec_types and not f_app_data:
                        f_app_data = True

                # 明文访问：srcIP 需有 > min_sessions 个完整会话（单次可能是客户端配置错误）
                if f_plaintext and _n_src_complete > _c('https', 'min_sessions'):
                    cats['plaintext-access'][dst_ip].extend(pkts)

                # 白名单检查：IP白名单 + SNI域名白名单
                # 放在所有分类判定之前，覆盖 Multiple_Hello/THC_SSL/
                # TLS_Incomplete/TLS_NullSession/AppData 等全部路径
                if (self.wl.hit_http(src_ip, dst_ip)
                        or (sni and self.wl.hit_http(src_ip, dst_ip, sni, ''))):
                    continue

                # 问题14：删除 Multiple_Hello 分类（原 client_hello_count>=2 直接 continue 跳过）
                if client_hello_count >= _c('https','client_hello_min'):
                    continue

                # THC-SSL：同一 TCP 连接内单次 ClientHello 但多次 CCS（>= 2），即多次重协商
                # 分布式攻击：每个 bot 仅建 1~2 个会话，不设 srcIP 会话数门槛（同 Client-Hello-Flood）
                if ccs_count >= _c('https','ccs_min'):
                    cats['THC_SSL'][dst_ip].extend(pkts)
                    continue

                # HTTPS 空连接：全量重组后仍无 ClientHello
                # 再取前10个有 payload 的包重组，尝试识别 ClientHello
                # 前10包重组后仍无 ClientHello → HTTPS-NullSession（ACK > 300）
                if not f_client_hello:
                    top10_tls = [t for t in tl
                                 if t['payload'] and not t['RST'] and not t['FIN']][:10]
                    if top10_tls:
                        top10_reasm_tls, _ = reassemble_tcp_payload(top10_tls)
                        if has_tls_client_hello(top10_reasm_tls):
                            f_client_hello = True
                            sni = extract_sni(top10_reasm_tls)
                            alpn_protocols = extract_alpn(top10_reasm_tls)
                            client_hello_count = max(client_hello_count, 1)
                            # 更新 CCS/AppData（前10包重组）
                            reasm_top10_types = _scan_tls_records(top10_reasm_tls)
                            if 0x14 in reasm_top10_types and not f_change_cipher:
                                f_change_cipher = True
                            if 0x17 in reasm_top10_types and not f_app_data:
                                f_app_data = True
                    if not f_client_hello:
                        # 前10包重组后仍无 ClientHello → HTTPS-NullSession
                        # 限制为 https_ports（默认443/8443），不扩散到其他端口
                        #
                        # 空洞检测：若抓包丢失了 SYN 之后的段（如分段 Client Hello 的第一段），
                        # 重组流不以 0x16 开头，三层检测均失败，会误判 NullSession。
                        # 通过比较第一个有效数据包 seq 与 ISN+1 来检测丢包空洞：
                        #   expected_first_seq = (SYN.seq + 1) & 0xFFFF_FFFF
                        #   若 first_data.seq > expected_first_seq → 存在未抓到的段
                        # 此时 Client Hello 可能藏在丢失的段中，跳过 NullSession 以免误报。
                        _syn_t = next((t for t in tl if t['SYN'] and not t['ACK']), None)
                        _has_seq_gap = False
                        if _syn_t:
                            _expected = (_syn_t['seq'] + 1) & 0xFFFFFFFF
                            _first_data = next(
                                (t for t in tl if t['payload'] and not t['SYN'] and not t['RST']),
                                None)
                            if _first_data:
                                _gap = (_first_data['seq'] - _expected) & 0xFFFFFFFF
                                # gap 在合理范围内（< 2GB）且非零 → 真实空洞
                                if 0 < _gap < 0x80000000:
                                    _has_seq_gap = True
                        if not _has_seq_gap:
                            if (dport in self.https_ports and has_syn
                                    and not f_plaintext and pure_ack > _c('tcp_state','null_session_pure_ack_min')):
                                cats['HTTPS-NullSession'][dst_ip].extend(pkts)
                        continue

                # 问题11：Client Hello Flood（原 TLS Incomplete Session）：有 ClientHello 但无 ChangeCipherSpec
                # 分布式攻击：每个 bot IP 只发 1~2 个不完整握手会话，不设 srcIP 会话数门槛
                # （与 HTTPS-NullSession / THC-SSL 性质相同，均属 TLS Handshake Flood 大类）
                # 变种 Client-Hello-FIN-Flood：ClientHello 与 FIN 在同一报文，攻击工具"发完即关"
                # 效率更高：单次攻击只需 2 个报文（SYN + ClientHello+FIN），无需等待服务端响应
                if not f_change_cipher:
                    if not f_app_data:
                        if f_hello_fin:
                            cats['Client-Hello-FIN-Flood'][dst_ip].extend(pkts)
                        else:
                            cats['Client-Hello-Flood'][dst_ip].extend(pkts)
                    continue

                # 问题12：Negotiation Abuse（原 TLS NullSession）：有 ChangeCipherSpec 但无 AppData
                # 分布式攻击：每个 bot IP 只完成 CCS 但不发 AppData，不设 srcIP 会话数门槛
                if not f_app_data:
                    cats['Negotiation-Abuse'][dst_ip].extend(pkts)
                    continue

                # ── 有完整 TLS + AppData 的分类 ────────────────────────────
                def _hadd(cat):
                    cats[cat][dst_ip].extend(pkts)

                matched_specific = False

                # SNI 为空时，再次尝试从重组流提取（分段 ClientHello 场景）
                if not sni and reassembled_https:
                    sni = extract_sni(reassembled_https)
                    if sni:
                        alpn_protocols = extract_alpn(reassembled_https) or alpn_protocols

                # Abnormal_SNI：SNI 为 IP 地址格式
                # srcIP 需有 > min_sessions 个完整会话（单次可能是客户端实现问题）
                # SNI 缺失不归类，由后续 CC 兜底
                if not sni:
                    pass  # 不单独归类，由后续 CC 兜底
                elif is_ip_address(sni) and _n_src_complete > _c('https', 'min_sessions'):
                    _hadd('Abnormal-SNI')
                    matched_specific = True

                # Same-Request-PktLen：累加到组级统计，不在此处触发
                # 组级判定（跨所有会话统计 80% 一致性）在外层循环结束后执行
                if app_data_lens:
                    grp_app_data_lens.extend(app_data_lens)
                    grp_all_pkts.extend(pkts)

                # RST 结束：srcIP 需有 > min_sessions 个完整会话（单次 RST 可能是正常连接中断）
                if ends_rst and _n_src_complete > _c('https', 'min_sessions'):
                    _hadd('RST-Session')
                    matched_specific = True

                # SlowAttack
                if has_slow_read:
                    _hadd('SlowRead')
                    matched_specific = True


                # BigResource（≥10个会话才判定）
                if big_resource and len(sport_sessions) >= _c('https','bigresource_min_sessions'):
                    _hadd('BigResource-Access')
                    matched_specific = True

                # MultipleAD per packet：srcIP 需有 > min_sessions 个完整会话
                if multi_ad_pkts and _n_src_complete > _c('https', 'min_sessions'):
                    _hadd('MultipleAD-perPacket')
                    matched_specific = True

                # HTTP/2 Rapid Reset（CVE-2023-44487）
                # 攻击者在单连接内大量发送 HEADERS + RST_STREAM 对，每个 stream 在服务器响应前即被取消，
                # 绕过 SETTINGS_MAX_CONCURRENT_STREAMS 限制，使服务器 CPU 耗尽。
                # TLS 层近似识别（RST_STREAM 帧加密不可见，以高 AppData 计数作为代理指标）：
                # 条件：h2 ALPN（无 http/1.x）
                #       + AppData TLS record ≥ http2_rapid_reset_appdata_min（默认500）
                #       + TCP RST 结束
                #       + 会话时长 ≤ http2_rapid_reset_duration（默认5秒）
                # 关键鉴别：正常 h2 连接（爬虫/浏览器探测）仅产生 2~4 个 AppData record，
                # 真实 Rapid Reset 每连接制造数百~数千 stream，对应数百以上 AppData record
                _has_h2_only = (
                    bool(alpn_protocols)
                    and any(p == 'h2' for p in alpn_protocols)
                    and not any(p.startswith('http/1') for p in alpn_protocols)
                )
                _sess_duration = (pkts[-1]['ts'] - pkts[0]['ts']) if len(pkts) >= 2 else 0
                if (_has_h2_only and ends_rst
                        and len(app_data_lens) >= _c('https', 'http2_rapid_reset_appdata_min')
                        and _sess_duration <= _c('https', 'http2_rapid_reset_duration')):
                    _hadd('HTTP2-Rapid-Reset')
                    matched_specific = True

                # Suspicious_HTTP2：HTTPS 应用层兜底类
                # 核心标识：ALPN 仅协商 h2 而无 http/1.x —— 这本身就是可疑信号
                #   正常客户端（Chrome/Firefox/curl 等）会同时声明 h2 与 http/1.1 以便回退，
                #   只声明 h2 通常是攻击工具或专用脚本（未实现协议回退逻辑）。
                # 量化门槛（仅做"真实 TLS 会话"过滤，不做攻击强度判定）：
                #   - 客户端 AppData record ≥ h2_suspicious_appdata_min（默认 1，过滤握手失败/空连接）
                #   - srcIP 完整会话数 ≥ h2_suspicious_min_sessions（默认 2，过滤单次偶发连接）
                # 注：已触发 HTTP2-Rapid-Reset 的会话不重复标记
                if alpn_protocols and not matched_specific:
                    has_h2      = any(p == 'h2' for p in alpn_protocols)
                    has_http1x  = any(p.startswith('http/1') for p in alpn_protocols)
                    if (has_h2 and not has_http1x
                            and len(app_data_lens) >= _c('https', 'h2_suspicious_appdata_min')
                            and _n_src_complete >= _c('https', 'h2_suspicious_min_sessions')):
                        _hadd('Suspicious-HTTP2')
                        matched_specific = True

                # Gov SNI：仅作为双写行业标记，不设 matched_specific
                # cats['Gov'] 已移除；gov 会话若未触发其他分类则落入 CC 兜底，
                # 由 https_gov_pairs 双写机制写出 Government/HTTPS/CC

                # CC：兜底（≥10个会话才判定）
                if not matched_specific and len(sport_sessions) >= _c('https','bigresource_min_sessions'):
                    _hadd('CC')

            # ── Same-Request-PktLen 组级判定 ──────────────────────────────────
            # 新定义：单个 srcIP 对同一 dstIP 的所有会话中，AppData 报文长度一致性
            # ≥ 80%，且每种长度指纹至少有 5 个命中，方可触发。
            # 例：12个 AppData，5个700B + 5个800B → 合格指纹10个，10/12=83.3% ≥ 80% → 触发
            if grp_app_data_lens:
                from collections import Counter as _Ctr
                _ctr         = _Ctr(grp_app_data_lens)
                _total       = len(grp_app_data_lens)
                _min_hits    = _c('https', 'same_pkt_len_min_pkts')       # 每种指纹最少命中数=5
                _consistency = _c('https', 'same_pkt_len_consistency')    # 一致性阈值=0.8
                _qualifying  = sum(cnt for cnt in _ctr.values() if cnt >= _min_hits)
                if _qualifying > 0 and _qualifying / _total >= _consistency:
                    cats['Same-Request-PktLen'][dst_ip].extend(grp_all_pkts)
                    # 从 CC 中去除已归入 Same-Request-PktLen 的报文（避免重叠写出）
                    _srp_ids = {id(p) for p in grp_all_pkts}
                    cats['CC'][dst_ip] = [p for p in cats['CC'][dst_ip]
                                          if id(p) not in _srp_ids]

        # HTTPS 行业标记：精确到 (src_ip,dst_ip) 对，只有该对有 gov SNI 才双写
        # 使用 TCP 分段重组后的流提取 SNI，避免分段 ClientHello 提取失败
        https_gov_pairs = set()
        for (src_ip, dst_ip), sport_sessions in src_dst.items():
            for sport, dport, pkts in sport_sessions:
                # 只从客户端包提取 SNI（ClientHello 由客户端发出）
                tl_gov = [p['tcp'] for p in pkts if p['src_ip'] == src_ip]
                found_gov = False
                for t in tl_gov:
                    if t['payload']:
                        s = extract_sni(t['payload'])
                        if s and 'gov' in s.lower():
                            https_gov_pairs.add((src_ip, dst_ip))
                            found_gov = True
                            break
                if not found_gov:
                    reasm_gov, _ = reassemble_tcp_payload(tl_gov)
                    if reasm_gov:
                        s = extract_sni(reasm_gov)
                        if s and 'gov' in s.lower():
                            https_gov_pairs.add((src_ip, dst_ip))

        dir_map = {
            'HTTPS-NullSession':   ('Application Attack/HTTPS/HTTPS NullSession',          'HTTPS-NullSession'),
            # 问题11：TLS Incomplete Session → Client Hello Flood，归入 TLS Handshake Flood
            'Client-Hello-Flood':     ('Application Attack/HTTPS/TLS Handshake Flood', 'Client-Hello-Flood'),
            # Client-Hello-FIN-Flood：CHF 变种，ClientHello 与 FIN 同包（"发完即关"）
            'Client-Hello-FIN-Flood': ('Application Attack/HTTPS/TLS Handshake Flood', 'Client-Hello-FIN-Flood'),
            # 问题12：TLS NullSession → Negotiation Abuse，归入 TLS Handshake Flood
            'Negotiation-Abuse':   ('Application Attack/HTTPS/TLS Handshake Flood',        'Negotiation-Abuse'),
            # 问题13：THC-SSL 归入 TLS Handshake Flood（文件名不变）
            'THC_SSL':             ('Application Attack/HTTPS/TLS Handshake Flood',        'THC-SSL'),
            'plaintext-access':    ('Application Attack/HTTPS/plaintext access',           'plaintext-access'),
            'Abnormal-SNI':        ('Application Attack/HTTPS/Abnormal SNI',               'Abnormal-SNI'),
            'Same-Request-PktLen':  ('Application Attack/HTTPS/Same Request PktLen',        'Same-Request-PktLen'),
            'RST-Session':         ('Application Attack/HTTPS/RST Session',                'RST-Session'),
            'SlowRead':            ('Application Attack/HTTPS/SlowAttack',                 'SlowRead'),
            'BigResource-Access':  ('Application Attack/HTTPS/BigResource Access',         'BigResource-Access'),
            'MultipleAD-perPacket':('Application Attack/HTTPS/MultipleAD perPacket Access','MultipleAD-perPacket'),
            'CC':                  ('Application Attack/HTTPS/CC',                         'EncryptedCC'),
            'Suspicious-HTTP2':    ('Application Attack/HTTPS/Suspicious HTTP2',           'Suspicious-HTTP2'),
            'HTTP2-Rapid-Reset':   ('Application Attack/HTTPS/HTTP2 Rapid Reset',          'HTTP2-Rapid-Reset'),
        }
        # THC_SSL / Client-Hello-Flood / Client-Hello-FIN-Flood / Negotiation-Abuse /
        # HTTP2-Rapid-Reset / HTTPS-NullSession 不受最小会话数限制（分布式攻击）
        # Suspicious-HTTP2 作为兜底类也不受此限制（核心标识"仅含h2 ALPN"已是可疑信号）
        no_threshold = {'THC_SSL', 'Client-Hello-Flood', 'Client-Hello-FIN-Flood',
                        'Negotiation-Abuse', 'HTTPS-NullSession', 'HTTP2-Rapid-Reset',
                        'Suspicious-HTTP2'}
        for cat, (subdir, suffix) in dir_map.items():
            for dst_ip, pkts in cats[cat].items():
                if cat in no_threshold or total_sess_by_dst[dst_ip] >= _c('http','min_sessions'):
                    self.save(subdir, dst_ip, suffix, pkts, verbose)

        # ── JA4 后处理（C+A 写出，D 元数据日志）───────────────────────────
        # A：JA4-Malicious（黑名单命中）—— 单会话即写出，文件名带 JA4 全串
        for (dst_ip, ja4_full, bl_pattern), pkts in ja4_malicious_pkts.items():
            self.save('Application Attack/HTTPS/JA4-Malicious', dst_ip,
                      f'JA4-Malicious_{ja4_full}', pkts, verbose)

        # C：JA4-Botnet 自聚类 —— 同 JA4 → 同 dst 出现 ≥ N 个不同 srcIP
        ja4_botnet_min = _c('ja4', 'botnet_min_src_ips', default=10)
        for (dst_ip, ja4_full), info in ja4_aggr.items():
            if len(info['srcs']) >= ja4_botnet_min:
                self.save('Application Attack/HTTPS/JA4-Botnet', dst_ip,
                          f'JA4-Botnet_{ja4_full}', info['pkts'], verbose)

        # D：元数据日志 —— verbose 模式打印 JA4 摘要供人工沉淀私有指纹库
        if verbose and ja4_observed:
            print(f'  [JA4] 本文件观测到 {len(ja4_observed)} 个 JA4 指纹:')
            for ja4, cnt in sorted(ja4_observed.items(), key=lambda x: -x[1])[:20]:
                _srcs = sum(len(info['srcs']) for (d, j), info in ja4_aggr.items() if j == ja4)
                print(f'    {ja4}  sessions={cnt}  srcIPs={_srcs}')

        # HTTPS 行业双写：合并所有 gov srcIP 的包后一次性 save
        https_gov_src_by_dst = collections.defaultdict(set)
        for (src_ip, dst_ip) in https_gov_pairs:
            https_gov_src_by_dst[dst_ip].add(src_ip)

        for dst_ip, gov_srcs in https_gov_src_by_dst.items():
            if total_sess_by_dst[dst_ip] < _c('http','min_sessions'):
                continue
            for cat, (subdir, suffix) in dir_map.items():
                if cat in ('Gov',):
                    continue
                all_pkts = cats[cat].get(dst_ip, [])
                if not all_pkts:
                    continue
                # 合并所有 gov srcIP 的包，一次 save
                src_pkts = [p for p in all_pkts if p['src_ip'] in gov_srcs]
                if not src_pkts:
                    continue
                ind_subdir = subdir.replace('Application Attack/HTTPS',
                                            'Application Attack/Government/HTTPS')
                self.save(ind_subdir, dst_ip, suffix, src_pkts, verbose)
    # ──────────────────────────────────────────────────────────────────────────
    # 六、QUIC
    # ──────────────────────────────────────────────────────────────────────────

    def classify_quic(self, parsed, verbose):
        """QUIC 两阶段分类器（v5.2）
        统一处理 dport=443（攻击请求）和 sport=443（反射响应），
        classify_udp_reflection 不再处理端口 443 的 QUIC 流量。

        dport=443 Phase-1 逐包桶：
          malformed        → Application Attack/QUIC/Malformed
          version_pkts     → Version=0 Long Header（后续按 srcIP 集中度分流）
          initial_pure     → Initial ≥1200B 且非 coalesced（后续按 srcIP 集中度 + per-srcIP DCID 分流）
          coalesced_pkts   → Initial ≥1200B 但含 coalesced Handshake（→ Handshake-Flood）
          zero_rtt_pkts    → PacketType=0x01（→ Zero-RTT-Flood）
          其余长头部(Handshake/Retry) 和短头部(1-RTT) 不单独写出

        dport=443 Phase-2 per-dstIP 聚合：
          version_pkts : unique_src ≤ THR_SRCIP → Version-Amplification-Request
                         unique_src >  THR_SRCIP → Version-Flood
          initial_pure : unique_src ≤ THR_SRCIP → Initial-Amplification-Request
                         unique_src >  THR_SRCIP, per-srcIP unique_dcid ≤ THR_DCID → Initial-Flood
                         unique_src >  THR_SRCIP, per-srcIP unique_dcid >  THR_DCID → CID-Exhaustion
          coalesced_pkts : 包数 ≥ THR_HF  → Handshake-Flood
          zero_rtt_pkts  : 包数 ≥ THR_ZRTT → Zero-RTT-Flood

        sport=443 分类：
          VN(version=0) 或 Retry(ptype=3) → Volumetric Attack/UDP/Amplification/dstIP_QUIC
          Fixed-Bit=0 + 包长 <50B         → Volumetric Attack/UDP/Reflection/dstIP_QUIC-Stateless-Reset
        """
        THR_SRCIP = _c('udp_reflection', 'srcip_concentrated_threshold')      # 50
        THR_DCID  = _c('quic', 'cid_exhaustion_dcid_min',  default=5)        # 5
        THR_HF    = _c('quic', 'handshake_flood_min',      default=100)      # 100
        THR_ZRTT  = _c('quic', 'zero_rtt_flood_min',       default=100)      # 100
        THR_SR_LEN= _c('quic', 'stateless_reset_max_len',  default=50)       # 50
        THR_REFL  = _c('min_pkts', 'udp_reflection')                         # 100
        THR_AMP   = _c('min_pkts', 'amp_request', default=50)                # 50
        THR_MAL   = _c('min_pkts', 'default')                                # 20

        # ── Phase 0：按方向分流 ────────────────────────────────────────────────
        by_dst_req  = collections.defaultdict(list)  # dport=443
        by_dst_refl = collections.defaultdict(list)  # sport=443

        for p in parsed:
            if p['proto'] != 17 or not p['udp']:
                continue
            pl = p['udp']['payload']
            if not pl:
                continue
            if p['dport'] == 443:
                # sport 属于其他已知反射端口（如 389/CLDAP 打向 443）→ 归 UDP 反射，跳过
                if p['sport'] in REFLECTION_PORTS_UDP and p['sport'] != 443:
                    continue
                by_dst_req[p['dst_ip']].append(p)
            elif p['sport'] == 443:
                by_dst_refl[p['dst_ip']].append(p)

        # ── sport=443：反射响应分类 ───────────────────────────────────────────
        for dst_ip, pkts in by_dst_refl.items():
            reflected       = []   # Version Negotiation + Retry
            stateless_reset = []

            for p in pkts:
                pl = p['udp']['payload']
                # Stateless Reset：Fixed Bit=0（bit6=0）+ 包长 <50B（RFC 9001 §10.3）
                if len(pl) < THR_SR_LEN and not (pl[0] & 0x40):
                    stateless_reset.append(p)
                    continue
                qi = parse_quic_initial(pl)
                if qi is None or not qi.get('long_header'):
                    continue
                version = qi.get('version', -1)
                ptype   = qi.get('packet_type', -1)
                if version == 0 or ptype == 3:   # VN 或 Retry
                    reflected.append(p)

            if reflected:
                self.save('Volumetric Attack/UDP/Amplification', dst_ip,
                          'QUIC', reflected, verbose, THR_REFL)
            if stateless_reset:
                self.save('Volumetric Attack/UDP/Reflection', dst_ip,
                          'QUIC-Stateless-Reset', stateless_reset, verbose, THR_REFL)

        # ── dport=443：请求 / Flood 分类 ──────────────────────────────────────
        for dst_ip, pkts in by_dst_req.items():
            # Phase-1 buckets
            malformed      = []
            version_pkts   = []
            initial_pure   = []
            coalesced_pkts = []
            zero_rtt_pkts  = []

            for p in pkts:
                pl    = p['udp']['payload']
                udp   = p['udp']
                sport = p['sport']

                # ── Malformed 基础检测 ─────────────────────────────────────
                if udp['length'] < _c('quic', 'min_udp_length'):
                    malformed.append(p); continue
                if 0 < sport < _c('quic', 'sport_min'):
                    malformed.append(p); continue
                if same_subnet_24(p['src_ip'], p['dst_ip']):
                    malformed.append(p); continue

                qi = parse_quic_initial(pl)
                if qi is None:
                    # 无法解析为合法 QUIC 包头（含 Fixed-Bit=0 长头部）
                    malformed.append(p); continue

                if not qi.get('long_header'):
                    # 短头部（1-RTT）：加密数据，无法细分攻击类型，跳过
                    continue

                version = qi.get('version', -1)
                ptype   = qi.get('packet_type', -1)

                if version == 0:
                    # Version Negotiation 探测包
                    version_pkts.append(p)

                elif ptype == 0:    # Initial
                    if udp['length'] < 1200:
                        # RFC 9000 §14.1：Initial datagram 必须 ≥ 1200B
                        malformed.append(p)
                    elif qi.get('coalesced'):
                        # Datagram 含 coalesced Handshake → 攻击者维持真实连接（CC 攻击）
                        coalesced_pkts.append(p)
                    else:
                        initial_pure.append(p)

                elif ptype == 1:    # 0-RTT
                    zero_rtt_pkts.append(p)

                # ptype==2 (Handshake standalone) 和 ptype==3 (Retry at dport=443)：
                # 不单独写出（Handshake 是会话证据；Retry 不应出现在 dport=443）

            # ── Phase-2：per-dstIP 聚合写出 ───────────────────────────────
            # Malformed
            if malformed:
                self.save('Application Attack/QUIC/Malformed', dst_ip,
                          'Malformed', malformed, verbose, THR_MAL)

            # Version packets：srcIP 集中度分流
            if version_pkts:
                unique_src = len({p['src_ip'] for p in version_pkts})
                if unique_src <= THR_SRCIP:
                    self.save('Volumetric Attack/UDP/Amplification Request', dst_ip,
                              'Version-Amplification-Request', version_pkts, verbose, THR_AMP)
                else:
                    self.save('Application Attack/QUIC', dst_ip,
                              'Version-Flood', version_pkts, verbose, THR_MAL)

            # Initial 纯包：srcIP 集中度 → Amplification Request / Initial-Flood / CID-Exhaustion
            if initial_pure:
                unique_src = len({p['src_ip'] for p in initial_pure})
                if unique_src <= THR_SRCIP:
                    # srcIP 集中：受害者 IP 被伪造，此服务器是反射放大点
                    self.save('Volumetric Attack/UDP/Amplification Request', dst_ip,
                              'Initial-Amplification-Request', initial_pure, verbose, THR_AMP)
                else:
                    # srcIP 分散：进一步按 per-srcIP unique DCID 数区分
                    src_dcids = collections.defaultdict(set)
                    for p in initial_pure:
                        qi2 = parse_quic_initial(p['udp']['payload'])
                        if qi2:
                            src_dcids[p['src_ip']].add(qi2.get('conn_id', b''))

                    cid_exhaustion_pkts = []
                    initial_flood_pkts  = []
                    for p in initial_pure:
                        if len(src_dcids[p['src_ip']]) > THR_DCID:
                            cid_exhaustion_pkts.append(p)
                        else:
                            initial_flood_pkts.append(p)

                    if cid_exhaustion_pkts:
                        self.save('Application Attack/QUIC', dst_ip,
                                  'CID-Exhaustion', cid_exhaustion_pkts, verbose, THR_MAL)
                    if initial_flood_pkts:
                        self.save('Application Attack/QUIC', dst_ip,
                                  'Initial-Flood', initial_flood_pkts, verbose, THR_MAL)

            # Handshake Flood（coalesced Initial+Handshake）
            if coalesced_pkts:
                self.save('Application Attack/QUIC', dst_ip,
                          'Handshake-Flood', coalesced_pkts, verbose, THR_HF)

            # Zero-RTT Flood
            if zero_rtt_pkts:
                self.save('Application Attack/QUIC', dst_ip,
                          'Zero-RTT-Flood', zero_rtt_pkts, verbose, THR_ZRTT)

    # ──────────────────────────────────────────────────────────────────────────
    # 七、DNS
    # ──────────────────────────────────────────────────────────────────────────

    def classify_dns(self, parsed, verbose):
        """DNS 分类：只看 dport==53（sport==53 是反射，走 UDP 反射分类）
        UDP 反射优先原则：sport 在任意已知 UDP 反射端口的包直接跳过，
        由 classify_udp_reflection 负责归类（例如 CLDAP 反射打向受害者
        53 端口时 sport=389，payload 非 DNS 但不应误判为 DNS Malformed）。
        """
        by_dst = collections.defaultdict(list)
        # DNS response flood：dport==53 且 sport>1024 的响应包（按 dstIP 统计）
        resp_by_dst = collections.defaultdict(list)
        for p in parsed:
            if p['proto'] != 17 or not p['udp']:
                continue
            if p['dport'] != DNS_PORT:   # 只看目的端口是53的包
                continue
            # UDP 反射优先原则：sport 在已知反射端口 → 归 classify_udp_reflection
            if p['sport'] in REFLECTION_PORTS_UDP:
                continue
            by_dst[p['dst_ip']].append(p)
            # DNS response flood：sport>1024 且是 DNS 响应报文
            if p['sport'] > 1024:
                pl = p['udp']['payload']
                dns_r = parse_dns(pl)
                if dns_r is not None and dns_r['is_response']:
                    resp_by_dst[p['dst_ip']].append(p)

        for dst_ip, pkts in by_dst.items():
            malformed     = []
            random_sub    = []
            nxdomain      = []
            samesubnet    = []
            query         = []
            query_any     = []   # qtype=255 ANY
            query_opt_rr  = []   # EDNS0 udp_size>=1500
            dns_sec       = []   # DO bit 置位（DNSSEC 标志）
            query_axfr    = []   # qtype=252 AXFR / 251 IXFR（区域传输，MB 级响应）
            query_dnskey  = []   # qtype=48 DNSKEY / 43 DS / 46 RRSIG（DNSSEC 记录放大）
            query_txt     = []   # qtype=16 TXT（SPF/DMARC/大文本，10–50× 放大）
            subdomains    = collections.Counter()
            domains_seen  = collections.Counter()
            query_pkts_for_stats = []

            for p in pkts:
                udp = p['udp']
                pl  = udp['payload']

                # 白名单
                if self.wl.hit_dns(p['src_ip'], p['dst_ip']):
                    continue

                # ── Malformed 判定 ────────────────────────────────────────
                mal = False
                if udp['length'] < 20:
                    mal = True
                if p['sport'] < 1024 and p['sport'] > 0:
                    mal = True
                if same_subnet_24(p['src_ip'], p['dst_ip']):
                    mal = True
                dns = parse_dns(pl)
                if dns is None:
                    mal = True
                elif dns['is_response']:
                    mal = True

                if mal:
                    malformed.append(p)
                    continue

                # ── 合法 query，统计域名特征 ─────────────────────────────
                # 域名白名单：先扫描所有 question，任意 name 命中则整包跳过
                dns_wl_hit = False
                for q in dns['questions']:
                    name = q['name'].lower()
                    if self.wl.hit_dns(p['src_ip'], p['dst_ip'], name):
                        dns_wl_hit = True
                        break
                if dns_wl_hit:
                    continue  # 整包跳过，不进入任何统计列表

                f_any = f_axfr = f_dnskey = f_txt = False
                for q in dns['questions']:
                    name = q['name'].lower()
                    parts = name.split('.')
                    if len(parts) >= 2:
                        domain    = '.'.join(parts[-2:])
                        subdomain = parts[0] if len(parts) >= 3 else ''
                        domains_seen[domain] += 1
                        if subdomain:
                            subdomains[subdomain] += 1
                    qt = q.get('qtype')
                    if qt == 255:           f_any    = True  # ANY
                    if qt in (251, 252):    f_axfr   = True  # IXFR / AXFR
                    if qt in (43, 46, 48):  f_dnskey = True  # DS / RRSIG / DNSKEY
                    if qt == 16:            f_txt    = True  # TXT
                if f_any:    query_any.append(p)
                if f_axfr:   query_axfr.append(p)
                if f_dnskey: query_dnskey.append(p)
                if f_txt:    query_txt.append(p)

                if same_subnet_24(p['src_ip'], p['dst_ip']):
                    samesubnet.append(p)

                # DNSSEC DO bit + OPT-RR udp size
                try:
                    ar_count = struct.unpack('>H', pl[10:12])[0]
                    if ar_count > 0:
                        idx = pl.find(b'\x00\x00\x29')
                        if idx >= 0 and idx + 9 <= len(pl):
                            # OPT record: name(1)+type(2)+udp_size(2)+ext(1)+ver(1)+Z(2)+rdlen(2)
                            udp_size = struct.unpack('>H', pl[idx+3:idx+5])[0]
                            z_field  = struct.unpack('>H', pl[idx+7:idx+9])[0]
                            if z_field & 0x8000:
                                dns_sec.append(p)
                            if udp_size >= _c('dns','opt_rr_udp_size'):
                                query_opt_rr.append(p)
                except Exception:
                    pass

                query_pkts_for_stats.append(p)
                query.append(p)

            # ── 子域名 / NXDOMAIN 判定 ────────────────────────────────────
            n_q = len(query_pkts_for_stats)
            if n_q >= 10:
                unique_subs = len(subdomains)
                unique_doms = len(domains_seen)
                if unique_subs > n_q * 0.5:
                    random_sub.extend(query_pkts_for_stats)
                elif unique_doms > n_q * 0.5:
                    nxdomain.extend(query_pkts_for_stats)

            # Malformed → Application Attack/DNS/Malformed
            if len(malformed) >= _c('dns','malformed_min'):
                self.save('Application Attack/DNS/Malformed', dst_ip,
                          'Malformed', malformed, verbose, _c('min_pkts','udp_reflection'))
            # Query → Application Attack/DNS/DNS Query Flood
            q_base = 'Application Attack/DNS/DNS Query Flood'
            if len(random_sub) >= _c('dns','random_sub_min'):
                self.save(q_base, dst_ip, 'random-subdomain', random_sub, verbose)
            if len(nxdomain) >= _c('dns','nxdomain_min'):
                self.save(q_base, dst_ip, 'NXDOMAIN',         nxdomain,   verbose)
            if len(samesubnet) >= _c('dns','samesubnet_min'):
                self.save(q_base, dst_ip, 'samesubnet-query', samesubnet, verbose)
            if len(dns_sec) >= _c('dns','dns_sec_min'):
                self.save(q_base, dst_ip, 'DNS-Sec',          dns_sec,    verbose)
            if len(query_any) >= _c('dns','query_any_min'):
                self.save(q_base, dst_ip, 'Query-ANY',        query_any,  verbose)
            if len(query_opt_rr) >= _c('dns','query_opt_rr_min'):
                self.save(q_base, dst_ip, 'Query-OPT-RR',     query_opt_rr,  verbose)
            if len(query_axfr) >= _c('dns','query_axfr_min'):
                self.save(q_base, dst_ip, 'Query-AXFR',       query_axfr,    verbose)
            if len(query_dnskey) >= _c('dns','query_dnskey_min'):
                self.save(q_base, dst_ip, 'Query-DNSKEY',     query_dnskey,  verbose)
            if len(query_txt) >= _c('dns','query_txt_min'):
                self.save(q_base, dst_ip, 'Query-TXT',        query_txt,     verbose)
            if len(query) >= _c('dns','query_min'):
                self.save(q_base, dst_ip, 'query',            query,         verbose)

        # DNS response Flood：sport>1024 且 DNS response 报文数 ≥50
        for dst_ip, pkts in resp_by_dst.items():
            self.save('Application Attack/DNS/DNS Response Flood', dst_ip,
                      'response', pkts, verbose, _c('min_pkts','udp_reflection'))


    def classify_sip(self, parsed, verbose):
        """SIP 分类：Malformed / INVITE / OPTIONS / REGISTER / Other Method
        SIP 完全支持非标端口，改为通过 payload is_sip() 识别，不限于 5060/5061
        """
        malformed_by_dst = collections.defaultdict(list)
        reflect_by_dst   = collections.defaultdict(list)
        # SIP Flood 按 Method 分类
        invite_by_dst    = collections.defaultdict(list)
        options_by_dst   = collections.defaultdict(list)
        register_by_dst  = collections.defaultdict(list)
        other_by_dst     = collections.defaultdict(list)

        for p in parsed:
            if p['proto'] != 17 or not p['udp']:
                continue
            pl = p['udp']['payload']
            if not pl:
                continue

            # UDP 反射优先原则：sport 在已知 UDP 反射端口 → 由 classify_udp_reflection
            # 处理，此处跳过。sport=5060 的 SIP/2.0 响应已由 classify_udp_reflection
            # 归 SIP 反射，无需在此重复写出；其他反射协议打向 SIP 端口时同理。
            if p['sport'] in REFLECTION_PORTS_UDP:
                continue

            # SIP 反射：payload 以 SIP/2.0 开头（服务端响应），
            # 且 dport 不是已知 SIP 端口（响应打向受害者）
            if pl[:7] == b'SIP/2.0' and p['dport'] not in SIP_PORTS:
                reflect_by_dst[p['dst_ip']].append(p)
                continue

            # SIP Flood：payload 必须是合法 SIP 请求（任意 dport）
            if not is_sip(pl):
                continue

            di  = p['dst_ip']

            # ── Malformed 判定 ─────────────────────────────────────────────
            mal = False
            if p['udp']['length'] < 20:
                mal = True
            if p['sport'] < 1024 and p['sport'] > 0:
                mal = True
            if same_subnet_24(p['src_ip'], p['dst_ip']):
                mal = True

            if mal:
                malformed_by_dst[di].append(p)
                continue

            # ── SIP Flood 按 Method 分类 ───────────────────────────────────
            if pl.startswith(b'INVITE'):
                invite_by_dst[di].append(p)
            elif pl.startswith(b'OPTIONS'):
                options_by_dst[di].append(p)
            elif pl.startswith(b'REGISTER'):
                register_by_dst[di].append(p)
            else:
                other_by_dst[di].append(p)

        flood_base = 'Application Attack/SIP/SIP Flood'
        for dst_ip, pkts in reflect_by_dst.items():
            self.save('Volumetric Attack/UDP/Reflection', dst_ip,
                      'SIP', pkts, verbose, _c('min_pkts','udp_reflection'))
        for dst_ip, pkts in malformed_by_dst.items():
            self.save('Application Attack/SIP/Malformed', dst_ip,
                      'Malformed', pkts, verbose, _c('min_pkts','udp_reflection'))
        for dst_ip, pkts in invite_by_dst.items():
            self.save(flood_base, dst_ip, 'SIP-INVITE',        pkts, verbose, _c('min_pkts','udp_reflection'))
        for dst_ip, pkts in options_by_dst.items():
            self.save(flood_base, dst_ip, 'SIP-OPTIONS',       pkts, verbose, _c('min_pkts','udp_reflection'))
        for dst_ip, pkts in register_by_dst.items():
            self.save(flood_base, dst_ip, 'SIP-REGISTER',      pkts, verbose, _c('min_pkts','udp_reflection'))
        for dst_ip, pkts in other_by_dst.items():
            self.save(flood_base, dst_ip, 'SIP-Other-Method',  pkts, verbose, _c('min_pkts','udp_reflection'))

    # ──────────────────────────────────────────────────────────────────────────
    # 九、DTLS
    # ──────────────────────────────────────────────────────────────────────────

    def classify_dtls(self, parsed, verbose):
        """DTLS 分类（5 种威胁类型）

        ① DTLS NullSession         – UDP 包发往 DTLS 端口但 payload 非合法 DTLS record
                                     （端口 443 跳过，防止 QUIC 包误归）
        ② DTLS ClientHello Flood   – 有合法 ClientHello（ht=1）但握手从未完成（无 Client CCS）
        ③ DTLS Fragment Exhaustion – ClientHello 第一分片发出但永不补全，耗尽重组缓冲区
        ④ DTLS State Exhaustion    – 握手完成（有 Client CCS）但无 AppData，反复建立空连接
        ⑤ DTLS CC Attack           – 完整会话（有 AppData）高频发起，持续耗尽服务器资源

        DTLS Record 头（13 字节）：
          content_type(1) + version(2,0xFExx) + epoch(2) + seq_no(6) + length(2)
          content_type: 20=ChangeCipherSpec  21=Alert  22=Handshake  23=ApplicationData

        Handshake 子类型（ct=22 时第 14 字节，即 pl[13]）：
          1=ClientHello  2=ServerHello  3=HelloVerifyRequest  11=Certificate
          12=ServerKeyExchange  14=ServerHelloDone  16=ClientKeyExchange  20=Finished

        DTLS 握手分片字段（ct=22 时，pl[14:25]）：
          hs_type(1) + msg_len(3) + msg_seq(2) + frag_offset(3) + frag_len(3)
        """
        DTLS_VERSIONS    = {0xfeff, 0xfefd, 0xfefc}  # DTLSv1.0 / 1.2 / 1.3
        DTLS_PURE_PORTS  = DTLS_PORTS - {443}         # 443 由 QUIC 分类器优先处理

        # ── 辅助：解析第一个 DTLS record header ──────────────────────────────
        def parse_dtls_record(pl: bytes):
            """返回 dict(ct, ver, epoch) 或 None（非合法 DTLS record）"""
            if len(pl) < 13:
                return None
            ct = pl[0]
            if ct not in (20, 21, 22, 23):
                return None
            ver = (pl[1] << 8) | pl[2]
            if ver not in DTLS_VERSIONS:
                return None
            epoch = (pl[3] << 8) | pl[4]
            return {'ct': ct, 'ver': ver, 'epoch': epoch}

        def get_handshake_type(pl: bytes):
            """content_type=22 时，pl[13] = handshake_type（需 len >= 14）"""
            return pl[13] if len(pl) >= 14 else None

        def is_fragment_incomplete(pl: bytes) -> bool:
            """检测 ClientHello 分片不完整：frag_offset=0 且 frag_len < msg_len
            DTLS Handshake 头结构（紧接 13 字节 Record 头之后）：
              hs_type(1:pl[13]) + msg_len(3:pl[14:17]) + msg_seq(2:pl[17:19])
              + frag_offset(3:pl[19:22]) + frag_len(3:pl[22:25])  → 共 25 字节
            注意 msg_seq 是 2 字节，frag_offset 从 pl[19] 开始而非 pl[17]
            """
            if len(pl) < 25 or pl[0] != 0x16:
                return False
            msg_len  = int.from_bytes(pl[14:17], 'big')
            frag_off = int.from_bytes(pl[19:22], 'big')  # msg_seq(2B) 之后
            frag_len = int.from_bytes(pl[22:25], 'big')
            return frag_off == 0 and 0 < frag_len < msg_len

        # ── Step 1: 收集所有发往 DTLS 端口的 UDP 包，按 dst_ip 分桶 ──────────
        by_dst: dict = collections.defaultdict(list)
        for p in parsed:
            if p['proto'] != 17 or not p['udp']:
                continue
            if p['dport'] not in DTLS_PORTS:
                continue
            by_dst[p['dst_ip']].append(p)

        # ── Step 2: 各类型分桶 ───────────────────────────────────────────────
        null_by_dst          = collections.defaultdict(list)   # ①
        ch_flood_by_dst      = collections.defaultdict(list)   # ②
        frag_exhaust_by_dst  = collections.defaultdict(list)   # ③
        state_exhaust_by_dst = collections.defaultdict(list)   # ④
        cc_by_dst            = collections.defaultdict(list)   # ⑤

        for dst_ip, all_pkts in by_dst.items():

            # ── 2a: 按 payload 合法性分离；非合法包归 NullSession ─────────────
            sessions: dict = collections.defaultdict(list)
            for p in all_pkts:
                pl = p['udp']['payload']
                if parse_dtls_record(pl) is None:
                    # 端口 443 上的非 DTLS UDP 包（QUIC 等）不归 NullSession
                    if p['dport'] in DTLS_PURE_PORTS:
                        null_by_dst[dst_ip].append(p)
                else:
                    key = (p['src_ip'], p['sport'], p['dst_ip'], p['dport'])
                    sessions[key].append(p)

            # ── 2b: 逐 session 分析握手完成程度 ──────────────────────────────
            for pkts in sessions.values():
                f_client_hello    = False  # ClientHello（ct=22, ht=1）
                f_fragment_incomp = False  # 第一分片存在但不完整
                f_ccs             = False  # Client ChangeCipherSpec（ct=20）
                f_app_data        = False  # AppData（ct=23）

                for p in pkts:
                    pl = p['udp']['payload']
                    rec = parse_dtls_record(pl)
                    if rec is None:
                        continue
                    ct = rec['ct']
                    if ct == 22:                          # Handshake
                        ht = get_handshake_type(pl)
                        if ht == 1:                       # ClientHello（严格比较 ht，非 ct）
                            f_client_hello = True
                            if is_fragment_incomplete(pl):
                                f_fragment_incomp = True
                    elif ct == 20:
                        f_ccs      = True                 # Client ChangeCipherSpec
                    elif ct == 23:
                        f_app_data = True                 # ApplicationData

                if not f_client_hello:
                    # 无 ClientHello：可能是响应包或乱序，归 NullSession
                    null_by_dst[dst_ip].extend(pkts)
                    continue

                # 有 ClientHello → 按握手完成程度分类
                if f_fragment_incomp and not f_ccs:
                    # ③ 分片第一片发出但不完整且握手从未完成
                    frag_exhaust_by_dst[dst_ip].extend(pkts)
                elif not f_ccs:
                    # ② ClientHello 已发出但无 CCS（握手从未完成）
                    ch_flood_by_dst[dst_ip].extend(pkts)
                elif not f_app_data:
                    # ④ 握手完成（有 CCS）但无 AppData
                    state_exhaust_by_dst[dst_ip].extend(pkts)
                else:
                    # ⑤ 完整会话
                    cc_by_dst[dst_ip].extend(pkts)

        # ── Step 3: 写出 ─────────────────────────────────────────────────────
        min_dtls = _c('min_pkts', 'dtls_incomplete')

        for dst_ip, pkts in null_by_dst.items():
            self.save('Application Attack/DTLS/DTLS NullSession',
                      dst_ip, 'DTLS-NullSession', pkts, verbose, min_dtls)
        for dst_ip, pkts in ch_flood_by_dst.items():
            self.save('Application Attack/DTLS/ClientHello Flood',
                      dst_ip, 'DTLS-ClientHello-Flood', pkts, verbose, min_dtls)
        for dst_ip, pkts in frag_exhaust_by_dst.items():
            self.save('Application Attack/DTLS/Fragment Exhaustion',
                      dst_ip, 'DTLS-Fragment-Exhaustion', pkts, verbose, min_dtls)
        for dst_ip, pkts in state_exhaust_by_dst.items():
            self.save('Application Attack/DTLS/State Exhaustion Attack',
                      dst_ip, 'State-exhaustion', pkts, verbose, min_dtls)
        for dst_ip, pkts in cc_by_dst.items():
            self.save('Application Attack/DTLS/CC Attack',
                      dst_ip, 'DTLS-CC', pkts, verbose, min_dtls)


# =============================================================================
# 主流程
# =============================================================================

def process_file(filepath, classifier, verbose=False):
    fname = os.path.basename(filepath)
    print(f'\n[>>] {fname}')

    raw = read_pcap(filepath)
    if not raw:
        print('  [跳过] 无有效包或读取失败')
        return

    parsed = parse_all(raw)
    print(f'  读取 {len(raw)} 包，解析 {len(parsed)} 包')

    sessions = tcp_sessions_by_key(parsed)
    classifier.written = 0

    # 一、网络层泛洪
    classifier.classify_syn_flood(parsed, verbose)
    classifier.classify_tcp_flood(parsed, verbose)
    classifier.classify_icmp_flood(parsed, verbose)
    classifier.classify_gre_flood(parsed, verbose)
    classifier.classify_tunnel_flood(parsed, verbose)
    classifier.classify_ip_flood(parsed, verbose)
    classifier.classify_udp_flood(parsed, verbose)
    classifier.classify_malformed(parsed, verbose)
    classifier.classify_fragments(parsed, verbose)

    # 二、反射
    classifier.classify_udp_reflection(parsed, verbose)
    classifier.classify_tcp_reflection(parsed, verbose)
    classifier.classify_http_reflection(parsed, verbose)

    # 三、TCP 连接类
    classifier.classify_tcp_state(sessions, verbose)
    classifier.classify_tcp_replay(sessions, verbose)

    # 四、HTTP
    classifier.classify_http(sessions, verbose)

    # 五、HTTPS
    classifier.classify_https(sessions, verbose)

    # 六、QUIC
    classifier.classify_quic(parsed, verbose)

    # 七、DNS
    classifier.classify_dns(parsed, verbose)

    # 八、SIP
    classifier.classify_sip(parsed, verbose)

    # 九、DTLS
    classifier.classify_dtls(parsed, verbose)

    if classifier.written == 0:
        print('  [完成] 未匹配任何攻击特征')
    else:
        print(f'  [完成] 写出 {classifier.written} 个文件')


def _worker(args):
    """多进程 worker：处理单个 pcap 文件，每个 worker 独立的 Classifier 实例。"""
    fp, output_root, wl_cfg, http_ports, https_ports, \
        botnet_threshold, slow_win, verbose, cfg_global, ja4_blacklist = args
    global CFG
    CFG = cfg_global
    namer      = FileNamer(output_root)
    classifier = Classifier(namer, wl_cfg, http_ports, https_ports,
                            botnet_threshold, slow_win, ja4_blacklist)
    try:
        process_file(fp, classifier, verbose)
        return fp, classifier.written, None
    except Exception as e:
        return fp, 0, str(e)


def main():
    parser = argparse.ArgumentParser(
        description='DDoS 攻击抓包全类型分类归档脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('patterns', nargs='*',
                        help='pcap 文件路径或通配符（可省略，省略时自动扫描当前目录下所有 *.pcap 和 *.cap）')
    parser.add_argument('--output',           default='./classified',
                        help='输出根目录（默认：./classified）')
    parser.add_argument('--http-ports',       default=None,
                        help='HTTP 端口，逗号分隔（默认来自配置文件，通常 80,8080）')
    parser.add_argument('--https-ports',      default=None,
                        help='HTTPS 端口，逗号分隔（默认来自配置文件，通常 443,8443）')
    parser.add_argument('--botnet-threshold', default=None, type=int,
                        help='SYN botnet 判定阈值，同一srcIP SYN数量（默认来自配置文件）')
    parser.add_argument('--slow-win',         default=None, type=int,
                        help='Slow/Sockstress 判定 TCP window size 上限（默认来自配置文件）')
    parser.add_argument('--config',           default=None,
                        help='阈值配置文件路径（YAML，默认与脚本同目录的 ddos_classifier.yaml）')
    parser.add_argument('--whitelist',        default=None,
                        help='白名单配置文件路径（JSON）')
    parser.add_argument('--ja4-blacklist',    default=None,
                        help='JA4 恶意指纹黑名单文件路径（JSON 数组，支持 * 通配；'
                             '默认查找脚本同目录 ja4_blacklist.json）')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='打印每个写出文件的路径和包数')
    parser.add_argument('--workers', '-j',    default=None, type=int,
                        help='并行进程数（默认：CPU 核数，-j 1 关闭多进程）')
    args = parser.parse_args()

    # ── 加载阈值配置（YAML） ──────────────────────────────────────────────
    global CFG
    CFG = _load_config(args.config)
    if args.config:
        print(f'阈值配置: {args.config}')

    cli_http   = args.http_ports   or ','.join(str(p) for p in _c('cli_defaults','http_ports',  default=[80,8080]))
    cli_https  = args.https_ports  or ','.join(str(p) for p in _c('cli_defaults','https_ports', default=[443,8443]))
    cli_botnet = args.botnet_threshold if args.botnet_threshold is not None else _c('cli_defaults','botnet_threshold', default=50)
    cli_slow   = args.slow_win         if args.slow_win         is not None else _c('cli_defaults','slow_win_threshold', default=10)

    try:
        http_ports  = set(int(p.strip()) for p in cli_http.split(',')  if p.strip())
        https_ports = set(int(p.strip()) for p in cli_https.split(',') if p.strip())
    except ValueError as e:
        sys.exit(f'[错误] 端口格式不正确: {e}')

    # ── 加载白名单配置（JSON） ────────────────────────────────────────────
    wl_cfg = dict(DEFAULT_WHITELIST)
    if args.whitelist:
        try:
            with open(args.whitelist, 'r', encoding='utf-8') as f:
                user_cfg = json.load(f)
            wl_cfg.update(user_cfg)
            print(f'白名单配置: {args.whitelist}')
        except Exception as e:
            print(f'[WARN] 白名单配置加载失败: {e}，使用默认白名单')

    # ── 加载 JA4 恶意指纹黑名单（JSON 数组）───────────────────────────────
    # 优先级：--ja4-blacklist 显式指定 > 脚本同目录 ja4_blacklist.json > 空集合
    ja4_bl_path = args.ja4_blacklist
    if not ja4_bl_path:
        _here   = os.path.dirname(os.path.abspath(__file__))
        _maybe  = os.path.join(_here, 'ja4_blacklist.json')
        if os.path.exists(_maybe):
            ja4_bl_path = _maybe
    ja4_blacklist = load_ja4_blacklist(ja4_bl_path) if ja4_bl_path else set()
    if ja4_blacklist:
        print(f'JA4 黑名单: {ja4_bl_path}  ({len(ja4_blacklist)} 条)')

    print(f'HTTP  端口: {sorted(http_ports)}')
    print(f'HTTPS 端口: {sorted(https_ports)}')
    print(f'botnet阈值: {cli_botnet}')
    print(f'slow-win  : {cli_slow}')
    print(f'输出目录  : {os.path.abspath(args.output)}')

    # 收集文件
    # 1) 未传任何参数 → 自动扫描当前目录下所有 *.pcap 与 *.cap（不递归）
    # 2) 传了参数 → 按通配符或文件路径解析；通配符不含扩展名时同时尝试 .pcap/.cap
    all_files = []
    if not args.patterns:
        # 默认行为：当前目录所有 pcap/cap 文件
        all_files.extend(glob.glob('*.pcap'))
        all_files.extend(glob.glob('*.cap'))
        if not all_files:
            sys.exit('[错误] 当前目录下未找到任何 .pcap / .cap 文件，'
                     '可显式传入文件路径或通配符')
    else:
        for pattern in args.patterns:
            matched = glob.glob(pattern, recursive=False)
            if not matched and os.path.isfile(pattern):
                matched = [pattern]
            if not matched:
                print(f'[WARN] 未找到匹配文件: {pattern}')
            all_files.extend(matched)

    # 过滤掉输出目录下的文件，避免对已分类结果再次处理
    _out_abs = os.path.abspath(args.output)
    all_files = sorted(set(
        os.path.abspath(f) for f in all_files
        if os.path.isfile(f) and not os.path.abspath(f).startswith(_out_abs + os.sep)
    ))
    if not all_files:
        sys.exit('[错误] 未找到任何 pcap 文件')

    # ── 确定并行度 ────────────────────────────────────────────────────────
    import multiprocessing as mp
    cpu_n     = mp.cpu_count()
    n_workers = args.workers if args.workers is not None else cpu_n
    n_workers = max(1, min(n_workers, len(all_files)))
    use_mp    = n_workers > 1

    print(f'共 {len(all_files)} 个文件待处理  '
          f'并行进程: {n_workers}{"（单进程模式）" if not use_mp else ""}')
    print('=' * 60)

    import time as _time
    t_start = _time.perf_counter()
    total_written = 0
    errors = []

    worker_args = [
        (fp, args.output, wl_cfg, http_ports, https_ports,
         cli_botnet, cli_slow, args.verbose, CFG, ja4_blacklist)
        for fp in all_files
    ]

    if use_mp:
        with mp.Pool(processes=n_workers) as pool:
            for fp, written, err in pool.imap_unordered(_worker, worker_args):
                fname = os.path.basename(fp)
                if err:
                    print(f'  [ERROR] {fname}: {err}')
                    errors.append((fp, err))
                else:
                    total_written += written
                    status = f'写出 {written} 个文件' if written else '未匹配任何攻击特征'
                    print(f'  [>>] {fname}  {status}')
    else:
        namer      = FileNamer(args.output)
        classifier = Classifier(namer, wl_cfg, http_ports, https_ports,
                                cli_botnet, cli_slow, ja4_blacklist)
        for fp in all_files:
            try:
                process_file(fp, classifier, args.verbose)
                total_written += classifier.written
            except Exception as e:
                print(f'  [ERROR] {fp}: {e}')
                errors.append((fp, str(e)))
                if args.verbose:
                    import traceback; traceback.print_exc()

    elapsed = _time.perf_counter() - t_start
    print(f'\n{"=" * 60}')
    print(f'全部完成。共写出 {total_written} 个文件，'
          f'耗时 {elapsed:.1f}s，速度 {len(all_files)/elapsed:.1f} 文件/s')
    if errors:
        print(f'[WARN] {len(errors)} 个文件处理失败：')
        for fp, e in errors:
            print(f'  {os.path.basename(fp)}: {e}')
    print(f'输出目录: {os.path.abspath(args.output)}')


if __name__ == '__main__':
    main()
