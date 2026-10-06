#!/system/bin/sh

DIR="/data/adb/mimosa"
cd "$DIR" || exit 1

# 1. 强制依赖检查（移至最顶端，避免产生孤儿进程）
TERMUX_BIN="/data/data/com.termux/files/usr/bin"
TERMUX_IP="$TERMUX_BIN/ip"
if [ ! -f "$TERMUX_IP" ]; then
    echo "[-] 致命错误：未找到 Termux 版 ip 工具。请在 Termux 中执行 pkg install iproute2"
    exit 1
fi
IP_CMD="env LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib $TERMUX_IP"

# 2. 准备日志环境并自动清理历史旧日志（保留最近 10 个）
mkdir -p "$DIR/log"
ls -1t "$DIR/log"/mimosa_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
ls -1t "$DIR/log"/sklookup_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null

LOG_TIME=$(date "+%Y%m%d%H%M")
LOG_FILE="$DIR/log/mimosa_${LOG_TIME}.log"
SK_LOG_FILE="$DIR/log/sklookup_${LOG_TIME}.log"

# 3. 赋予执行权限并启动 Mihomo
chmod +x "$DIR/mihomo" "$DIR/sklookup" 2>/dev/null
"$DIR/mihomo" -d "$DIR" > "$LOG_FILE" 2>&1 &
MIHOMO_PID=$!

# 等待 7891 端口监听就绪（优先调用 Termux ss，无环境则探查 /proc/net/tcp）
READY=0
SS_CMD="env LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib $TERMUX_BIN/ss"
for i in 1 2 3 4 5; do
    sleep 1
    if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
        echo "[-] Mihomo 启动崩溃，退出" >> "$LOG_FILE"
        sh "$DIR/stop.sh"
        exit 1
    fi
    if [ -f "$TERMUX_BIN/ss" ] && $SS_CMD -tln 2>/dev/null | grep -q ":7891 "; then
        READY=1; break
    elif grep -q ":1ED3 " /proc/net/tcp 2>/dev/null; then # 1ED3 为 7891 十六进制
        READY=1; break
    fi
done

if [ "$READY" -ne 1 ]; then
    echo "[-] 等待 7891 端口超时，启动终止" >> "$LOG_FILE"
    sh "$DIR/stop.sh"
    exit 1
fi

# 4. 策略路由体系配置
$IP_CMD route flush table 80 2>/dev/null
$IP_CMD route add local default dev lo src 127.0.0.1 table 80

# 4.1 掐断发往 Fake-IP 的 UDP（QUIC 0ms 退回 TCP）
$IP_CMD rule add to 198.18.0.0/16 ipproto 17 type unreachable pref 7990 2>/dev/null

# 4.2 阻断普通应用外网 IPv6 直连（精确定位 2000::/3，放行局域网 fe80::，防真实 IP 泄露）
$IP_CMD -6 rule add to 2000::/3 uidrange 10000-99999 type unreachable pref 8000 2>/dev/null

# 4.3 劫持全机所有访问 Fake-IP 的 TCP 流量（覆盖 update_engine 等系统组件）
$IP_CMD rule add to 198.18.0.0/16 ipproto 6 lookup 80 pref 8000 2>/dev/null

# 4.4 放行局域网私网 TCP（跳过 pref 8990/9000，保障 Quick Share / Wi-Fi Direct 原生直连）
$IP_CMD rule add to 10.0.0.0/8 goto 9001 pref 8900 2>/dev/null
$IP_CMD rule add to 172.16.0.0/12 goto 9001 pref 8901 2>/dev/null
$IP_CMD rule add to 192.168.0.0/16 goto 9001 pref 8902 2>/dev/null

# 4.5 【核心改动：替代 iptables】捕获普通应用的公网 UDP DNS 出站，引流至 table 80 触发 sk_lookup
# 注：限定 uidrange 10000-99999，彻底放行 UID 0（Mihomo 本身），杜绝上游解析死锁
$IP_CMD rule add uidrange 10000-99999 ipproto 17 dport 53 lookup 80 pref 8990 2>/dev/null

# 4.6 捕获普通应用公网 TCP 出站
$IP_CMD rule add uidrange 10000-99999 ipproto 6 lookup 80 pref 9000 2>/dev/null

# 5. 拉起 sklookup 并挂载 eBPF Link（同时接管 TCP 7891 与 UDP 53 -> TPROXY 7891）
"$DIR/sklookup" "$MIHOMO_PID" 7891 > "$SK_LOG_FILE" 2>&1 &
SK_PID=$!
sleep 1

if ! kill -0 "$SK_PID" 2>/dev/null; then
    echo "[-] sklookup 启动失败" >> "$LOG_FILE"
    sh "$DIR/stop.sh"
    exit 1
fi

echo "[+] Mimosa eBPF 透明代理启动成功（已完全移除 iptables）"
exit 0