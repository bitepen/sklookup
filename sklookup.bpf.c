#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MIHOMO_PORT 7891

/* 存放 Mihomo TCP 监听 Socket 的 Sockmap */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} redirect_socket SEC(".maps");

/* 存放 Mihomo PID 的单元素配置表，用于旁路自身流量 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

/* 判断当前系统调用是否来自 Mihomo 自身 */
static __always_inline int is_mihomo_process(void)
{
    __u32 key = 0;
    __u32 *target_pid = bpf_map_lookup_elem(&config_map, &key);
    if (target_pid && *target_pid != 0) {
        __u32 cur_pid = bpf_get_current_pid_tgid() >> 32;
        if (cur_pid == *target_pid)
            return 1;
    }
    return 0;
}

/* 1. 业务 TCP 流量透明分发 (sk_lookup) */
SEC("sk_lookup")
int sk_lookup_redirect(struct bpf_sk_lookup *ctx)
{
    __u32 key = 0;
    struct bpf_sock *sk;

    if (ctx->protocol != IPPROTO_TCP)
        return SK_PASS;

    if (ctx->local_port == MIHOMO_PORT)
        return SK_PASS;

    if (ctx->local_port != 80 && ctx->local_port != 443)
        return SK_PASS;

    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}

/* 2. 拦截 IPv4 connect()：将 UDP 53 重定向到 127.0.0.1:1053 */
SEC("cgroup/connect4")
int dns_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    if (is_mihomo_process())
        return 1;

    if (ctx->user_port == bpf_htons(53)) {
        ctx->user_ip4 = bpf_htonl(0x7f000001); // 127.0.0.1
        ctx->user_port = bpf_htons(1053);
    }
    return 1;
}

/* 3. 拦截 IPv4 sendmsg()：覆盖无连接 UDP 53 发包 */
SEC("cgroup/sendmsg4")
int dns_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    if (is_mihomo_process())
        return 1;

    if (ctx->user_port == bpf_htons(53)) {
        ctx->user_ip4 = bpf_htonl(0x7f000001); // 127.0.0.1
        ctx->user_port = bpf_htons(1053);
    }
    return 1;
}

/* 4. 拦截 IPv6 connect()：发往 53 端口瞬间拒绝，促使系统解析器秒级回退 IPv4 */
SEC("cgroup/connect6")
int dns_connect6(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    if (is_mihomo_process())
        return 1;

    if (ctx->user_port == bpf_htons(53))
        return 0; // 拒绝连接

    return 1;
}

/* 5. 拦截 IPv6 sendmsg()：覆盖无连接 IPv6 UDP 53 发包 */
SEC("cgroup/sendmsg6")
int dns_sendmsg6(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    if (is_mihomo_process())
        return 1;

    if (ctx->user_port == bpf_htons(53))
        return 0; // 拒绝发包

    return 1;
}