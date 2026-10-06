#!/system/bin/sh

DIR="/data/adb/mimosa"

# 1. 确定 iproute2 工具集
TERMUX_IP="/data/data/com.termux/files/usr/bin"
if [ -f "$TERMUX_IP/ip" ]; then
    IP_CMD="env LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib $TERMUX_IP/ip"
else
    IP_CMD="ip" # 降级回退
fi

# 2. 先撤规则：网络流量瞬间无感切回物理直连
# 循环清理所有指向 table 80 的规则（涵盖 pref 8000, 8990, 9000）
$IP_CMD rule show 2>/dev/null | grep "lookup 80" | while read -r line; do
    pref="${line%%:*}"
    [ -n "$pref" ] && $IP_CMD rule del pref "$pref" 2>/dev/null
done

# 显式清理单条规则（双重保险）
$IP_CMD rule del pref 8990 2>/dev/null
$IP_CMD rule del pref 7990 2>/dev/null
$IP_CMD rule del to 198.18.0.0/16 ipproto 17 type unreachable 2>/dev/null

# 清理私网跳过规则
$IP_CMD rule del pref 8900 2>/dev/null
$IP_CMD rule del pref 8901 2>/dev/null
$IP_CMD rule del pref 8902 2>/dev/null

# 清理 IPv6 阻断规则
$IP_CMD -6 rule del pref 8000 2>/dev/null
$IP_CMD -6 rule del to 2000::/3 uidrange 10000-99999 type unreachable 2>/dev/null

# 清空 table 80
$IP_CMD route flush table 80 2>/dev/null

# 3. 后杀进程：优雅退出 eBPF 与核心
pkill -15 sklookup 2>/dev/null
pkill -15 -f "$DIR/mihomo" 2>/dev/null
pkill -15 mihomo 2>/dev/null

sleep 0.3

# 兜底强杀
pkill -9 sklookup 2>/dev/null
pkill -9 -f "$DIR/mihomo" 2>/dev/null
pkill -9 mihomo 2>/dev/null

exit 0