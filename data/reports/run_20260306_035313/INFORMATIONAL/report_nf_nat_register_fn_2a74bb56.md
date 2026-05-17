# [INFORMATIONAL] Out Of Bounds Array Access in nf_nat_register_fn (CWE-119)

**Generated:** 2026-03-06T04:00:18.412752+00:00  
**Report ID:** `nf_nat_register_fn_2a74bb56`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_nat_core.c` |
| Function | `nf_nat_register_fn` |
| Line | 1015 |
| Subsystem | net |

## Source Code

```c
 1015 | int nf_nat_register_fn(struct net *net, u8 pf, const struct nf_hook_ops *ops,
 1016 | 		       const struct nf_hook_ops *orig_nat_ops, unsigned int ops_count)
 1017 | {
 1018 | 	struct nat_net *nat_net = net_generic(net, nat_net_id);
 1019 | 	struct nf_nat_hooks_net *nat_proto_net;
 1020 | 	struct nf_nat_lookup_hook_priv *priv;
 1021 | 	unsigned int hooknum = ops->hooknum;
 1022 | 	struct nf_hook_ops *nat_ops;
 1023 | 	int i, ret;
 1024 | 
 1025 | 	if (WARN_ON_ONCE(pf >= ARRAY_SIZE(nat_net->nat_proto_net)))
 1026 | 		return -EINVAL;
 1027 | 
 1028 | 	nat_proto_net = &nat_net->nat_proto_net[pf];
 1029 | 
 1030 | 	for (i = 0; i < ops_count; i++) {
 1031 | 		if (orig_nat_ops[i].hooknum == hooknum) {
 1032 | 			hooknum = i;
 1033 | 			break;
 1034 | 		}
 1035 | 	}
 1036 | 
 1037 | 	if (WARN_ON_ONCE(i == ops_count))
 1038 | 		return -EINVAL;
 1039 | 
 1040 | 	mutex_lock(&nf_nat_proto_mutex);
 1041 | 	if (!nat_proto_net->nat_hook_ops) {
 1042 | 		WARN_ON(nat_proto_net->users != 0);
 1043 | 
 1044 | 		nat_ops = kmemdup(orig_nat_ops, sizeof(*orig_nat_ops) * ops_count, GFP_KERNEL);
 1045 | 		if (!nat_ops) {
 1046 | 			mutex_unlock(&nf_nat_proto_mutex);
 1047 | 			return -ENOMEM;
 1048 | 		}
 1049 | 
 1050 | 		for (i = 0; i < ops_count; i++) {
 1051 | 			priv = kzalloc(sizeof(*priv), GFP_KERNEL);
 1052 | 			if (priv) {
 1053 | 				nat_ops[i].priv = priv;
 1054 | 				continue;
 1055 | 			}
 1056 | 			mutex_unlock(&nf_nat_proto_mutex);
 1057 | 			while (i)
 1058 | 				kfree(nat_ops[--i].priv);
 1059 | 			kfree(nat_ops);
 1060 | 			return -ENOMEM;
 1061 | 		}
 1062 | 
 1063 | 		ret = nf_register_net_hooks(net, nat_ops, ops_count);
 1064 | 		if (ret < 0) {
 1065 | 			mutex_unlock(&nf_nat_proto_mutex);
 1066 | 			for (i = 0; i < ops_count; i++)
 1067 | 				kfree(nat_ops[i].priv);
 1068 | 			kfree(nat_ops);
 1069 | 			return ret;
 1070 | 		}
 1071 | 
 1072 | 		nat_proto_net->nat_hook_ops = nat_ops;
 1073 | 	}
 1074 | 
 1075 | 	nat_ops = nat_proto_net->nat_hook_ops;
 1076 | 	priv = nat_ops[hooknum].priv;
 1077 | 	if (WARN_ON_ONCE(!priv)) {
 1078 | 		mutex_unlock(&nf_nat_proto_mutex);
 1079 | 		return -EOPNOTSUPP;
 1080 | 	}
 1081 | 
 1082 | 	ret = nf_hook_entries_insert_raw(&priv->entries, ops);
 1083 | 	if (ret == 0)
 1084 | 		nat_proto_net->users++;
 1085 | 
 1086 | 	mutex_unlock(&nf_nat_proto_mutex);
 1087 | 	return ret;
 1088 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-119 |
| Type | out_of_bounds_array_access |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

Line 1076 contains a critical OOB array access vulnerability. After the mutex-protected block (lines 1041-1073) that may allocate and assign `nat_proto_net->nat_hook_ops`, line 1075 reloads `nat_ops = nat_proto_net->nat_hook_ops` (which could be a pre-existing allocation from a prior call). The index used is `hooknum`, which was reassigned on line 1032 to the loop iteration index `i` (range [0, ops_count-1]) during the search loop (lines 1030-1035). However, `nat_ops` now points to the EXISTING allocation, which may have been sized for a DIFFERENT `orig_nat_ops` array (e.g., `nf_nat_ipv6_ops` vs `nf_nat_ipv4_ops`). More critically: in `nf_nat_ipv4_register_fn` (line 769), `ops->pf` is passed directly as `pf` without being validated against the actual protocol family expected by `nf_nat_ipv4_ops`. The `hooknum` remapping loop translates `ops->hooknum` to the index `i` within `orig_nat_ops`. If `ops->hooknum` matches no entry, WARN_ON_ONCE fires and returns -EINVAL (line 1037-1038) — safe. BUT: the `nat_ops[hooknum].priv` access on line 1076 uses the remapped `hooknum` (0 to ops_count-1) as an index into `nat_proto_net->nat_hook_ops`, which was allocated in a PRIOR call potentially with a DIFFERENT `ops_count`. There is no check that `hooknum < size_of_existing_nat_ops_array`. The existing allocation's size is never stored; it is implicitly trusted. A second caller with a larger `ops_count` or different `hooknum` value than the original allocation could index beyond the allocated array.

Additionally, integer overflow risk at line 1044: `sizeof(*orig_nat_ops) * ops_count` — if `ops_count` is attacker-influenced (e.g., via a crafted nftables/iptables rule), this multiplication could overflow on 32-bit size_t paths, producing an undersized allocation, with subsequent `nat_ops[i].priv` writes going OOB.

Secondary concern (P7/UAF): The `priv` pointer stored in `nat_ops[i].priv` (a `struct nf_nat_lookup_hook_priv`) is allocated per-slot. If `nf_hook_entries_insert_raw` fails after `nat_proto_net->nat_hook_ops` is set and users incremented, a subsequent `nf_nat_unregister_fn` call could race and free the priv while a hook callback is mid-execution, since hook entries use RCU but `priv->entries` modification is not fully RCU-safe during the insert path.

## Impact

None demonstrable; the structural constraints of the call graph prevent the cross-array-size indexing scenario required for OOB access

## Attack Path

```
nft_nat_inet_reg (nft_chain_nat.c:78) → nf_nat_inet_register_fn (nf_nat_proto.c:1021) → nf_nat_register_fn (nf_nat_core.c:1015). Alternatively: nfta_chain_type registration via nf_tables netlink → nft_nat_inet_reg → nf_nat_inet_register_fn → nf_nat_register_fn:1076 OOB read/write. Userspace path: socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) + NFT_MSG_NEWCHAIN with nat chain type → triggers chain type ->register callback → reaches nf_nat_register_fn. Requires CAP_NET_ADMIN.
```

## Check-Bypass Analysis

1. `nf_nat_ipv4_register_fn` passes `ops->pf` directly as the `pf` argument (line 769) with no validation other than the ARRAY_SIZE check at line 1025. The `pf` value indexes `nat_net->nat_proto_net[]` — if `ops->pf` is under caller control and can be set to an unexpected protocol family, the WARN_ON_ONCE at line 1025 is the only guard; it does NOT abort execution in production kernels (WARN_ON_ONCE continues). Wait — actually line 1025-1026 returns -EINVAL, so that path IS guarded. However, `nf_nat_ipv4_register_fn` passes `ops->pf` without first checking it equals NFPROTO_IPV4, unlike `nf_nat_inet_register_fn` which checks for NFPROTO_INET (line 1025 in nf_nat_proto.c). So a caller providing an ops with wrong pf to `nf_nat_ipv4_register_fn` could pass an arbitrary `pf` value to `nf_nat_register_fn`.
2. The critical bypass: line 1076 `nat_ops[hooknum].priv` — `hooknum` is validated to be in [0, ops_count-1] for the CURRENT call's `orig_nat_ops`, but `nat_ops` may point to a PREVIOUSLY allocated array of DIFFERENT size (from a prior registration with smaller ops_count). There is NO check that `hooknum < length_of_nat_ops`. The size of the existing allocation is not tracked anywhere.
3. `ops_count` integer overflow: `sizeof(*orig_nat_ops) * ops_count` at line 1044 — if ops_count approaches SIZE_MAX/sizeof(nf_hook_ops), this overflows producing a small allocation, followed by full-size writes.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Each protocol family (pf) value is always paired with the same compile-time-sized orig_nat_ops array. The nat_hook_ops allocation for pf=NFPROTO_IPV4 is always ARRAY_SIZE(nf_nat_ipv4_ops) entries; subsequent calls with pf=NFPROTO_IPV4 always pass nf_nat_ipv4_ops, so hooknum∈[0,ARRAY_SIZE(nf_nat_ipv4_ops)-1] is always in bounds. No caller can supply a different ops_count for the same pf after initial allocation. ops_count is always ARRAY_SIZE() of a static kernel array — not attacker-influenced. The nf_nat_ipv4_register_fn(ops->pf) path is gated by WARN_ON_ONCE+return-EINVAL for out-of-range pf values.

**False-positive reason:** The alleged OOB relies on a scenario where `nat_proto_net->nat_hook_ops` was allocated for one `orig_nat_ops` array size but later accessed with an index derived from a different, larger `orig_nat_ops`. In practice this cannot occur: each `pf` value is always paired with the same fixed `orig_nat_ops` array across all callers (`NFPROTO_IPV4` always uses `nf_nat_ipv4_ops`, `NFPROTO_IPV6` always uses `nf_nat_ipv6_ops`). The initial allocation uses `ARRAY_SIZE(orig_nat_ops)` elements, and subsequent calls with the same `pf` always pass the same `orig_nat_ops` — so `hooknum` (remapped to [0, ARRAY_SIZE(orig_nat_ops)-1]) is always within bounds of the existing allocation. The `ops_count` integer overflow claim also fails because `ops_count` is always a compile-time `ARRAY_SIZE()` constant, not attacker-controlled. The `ops->pf` validation concern in `nf_nat_ipv4_register_fn` is guarded by the WARN_ON_ONCE+return -EINVAL at line 1025-1026. No realistic exploit path exists for the described OOB.

## Remediation

No remediation required; the alleged vulnerability is a false positive based on incorrect assumptions about caller behavior. The call structure ensures invariant pf↔orig_nat_ops pairing.

---
*Graph vulnerability score: 12.73 | Betweenness: 0.0000 | PageRank: 0.000343*
