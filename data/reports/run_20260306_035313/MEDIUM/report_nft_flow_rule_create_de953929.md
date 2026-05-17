# [MEDIUM] Heap Buffer Overflow / Out-Of-Bounds Write (P2/P3) in nft_flow_rule_create (CWE-787)

**Generated:** 2026-03-06T04:04:53.177643+00:00  
**Report ID:** `nft_flow_rule_create_de953929`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_tables_offload.c` |
| Function | `nft_flow_rule_create` |
| Line | 48 |
| Subsystem | net |

## Source Code

```c
   48 | struct nft_flow_rule *nft_flow_rule_create(struct net *net,
   49 | 					   const struct nft_rule *rule)
   50 | {
   51 | 	struct nft_offload_ctx *ctx;
   52 | 	struct nft_flow_rule *flow;
   53 | 	int num_actions = 0, err;
   54 | 	struct nft_expr *expr;
   55 | 
   56 | 	expr = nft_expr_first(rule);
   57 | 	while (nft_expr_more(rule, expr)) {
   58 | 		if (expr->ops->offload_flags & NFT_OFFLOAD_F_ACTION)
   59 | 			num_actions++;
   60 | 
   61 | 		expr = nft_expr_next(expr);
   62 | 	}
   63 | 
   64 | 	if (num_actions == 0)
   65 | 		return ERR_PTR(-EOPNOTSUPP);
   66 | 
   67 | 	flow = nft_flow_rule_alloc(num_actions);
   68 | 	if (!flow)
   69 | 		return ERR_PTR(-ENOMEM);
   70 | 
   71 | 	expr = nft_expr_first(rule);
   72 | 
   73 | 	ctx = kzalloc(sizeof(struct nft_offload_ctx), GFP_KERNEL);
   74 | 	if (!ctx) {
   75 | 		err = -ENOMEM;
   76 | 		goto err_out;
   77 | 	}
   78 | 	ctx->net = net;
   79 | 	ctx->dep.type = NFT_OFFLOAD_DEP_UNSPEC;
   80 | 
   81 | 	while (nft_expr_more(rule, expr)) {
   82 | 		if (!expr->ops->offload) {
   83 | 			err = -EOPNOTSUPP;
   84 | 			goto err_out;
   85 | 		}
   86 | 		err = expr->ops->offload(ctx, flow, expr);
   87 | 		if (err < 0)
   88 | 			goto err_out;
   89 | 
   90 | 		expr = nft_expr_next(expr);
   91 | 	}
   92 | 	flow->proto = ctx->dep.l3num;
   93 | 	kfree(ctx);
   94 | 
   95 | 	return flow;
   96 | err_out:
   97 | 	kfree(ctx);
   98 | 	nft_flow_rule_destroy(flow);
   99 | 
  100 | 	return ERR_PTR(err);
  101 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **MEDIUM** |
| CVSS Score | 4.4 |
| CWE | CWE-787 |
| Type | heap_buffer_overflow / out-of-bounds write (P2/P3) |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | LOW |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

nft_flow_rule_create() contains a TOCTOU-style mismatch between two separate walks of the rule's expression list. In the first walk (lines 56-62), it counts only expressions whose offload_flags include NFT_OFFLOAD_F_ACTION to compute num_actions. This value is passed to nft_flow_rule_alloc(num_actions), which calls flow_rule_alloc(num_actions) to allocate a flow->rule with an actions array sized for exactly num_actions entries. In the second walk (lines 81-91), however, the code calls expr->ops->offload(ctx, flow, expr) for EVERY expression that has a non-NULL offload pointer — not just those flagged as NFT_OFFLOAD_F_ACTION. Each offload callback can populate a slot in flow->rule->action.entries[]. If any expression writes an action entry without checking the flagged count (i.e., if expressions without NFT_OFFLOAD_F_ACTION also write to the action array, or if an expression has both a non-NULL ->offload callback and writes an action entry without the flag being set), the number of action slots written in the second walk can exceed num_actions, resulting in an out-of-bounds write into the heap-allocated actions array. This is a classic allocate-N / write-M pattern where M > N due to asymmetric accounting between two independent list traversals.

Additionally, under concurrent rule modification (e.g., another thread calling nft_delrule or nft_newrule while this function is executing), the rule expression list could change between the two walks. The first walk (lines 56-62) is not protected by any explicit lock visible in this function. If num_actions is computed on a partially-constructed or partially-deleted rule expression list, the allocated actions array size will be wrong. The second walk would then write beyond the allocated buffer.

## Impact

Theoretical heap OOB write in the action entries array only if a specific expression type misimplements the NFT_OFFLOAD_F_ACTION flag contract; no such expression has been demonstrated to exist in the codebase.

## Attack Path

```
Userspace (CAP_NET_ADMIN in a user namespace) → netlink(NFNL_SUBSYS_NFTABLES, NFT_MSG_DELRULE) → nf_tables_delrule() → nft_delrule() [line 370: chain has NFT_CHAIN_HW_OFFLOAD flag] → nft_flow_rule_create() → first walk counts N actions (for ACTION-flagged exprs) → nft_flow_rule_alloc(N) allocates array of N action slots → second walk calls ->offload() for all exprs with non-NULL offload, potentially writing >N action entries → heap OOB write in flow->rule->action.entries[]
```

## Check-Bypass Analysis

1. Permission bypass: CAP_NET_ADMIN is required, but user namespaces allow unprivileged users to obtain this capability in their own namespace, making this reachable without true root. 2. NFT_CHAIN_HW_OFFLOAD flag: nft_delrule() only calls nft_flow_rule_create() when ctx->chain->flags & NFT_CHAIN_HW_OFFLOAD. An attacker can create a chain with hw_offload=1 via NFT_MSG_NEWCHAIN with NFTA_CHAIN_FLAGS set to NFT_CHAIN_HW_OFFLOAD — this is under attacker control. 3. The core logic bug: nft_flow_rule_alloc() receives num_actions counted from expressions with NFT_OFFLOAD_F_ACTION set. But flow_rule_alloc() allocates: sizeof(*flow_rule) + num_actions * sizeof(struct flow_action_entry). The second walk calls ->offload() for ALL expressions with a non-NULL ->offload pointer. Any expression type that has ->offload set but does NOT set NFT_OFFLOAD_F_ACTION in offload_flags, yet still writes an action entry inside its ->offload callback, creates an OOB write. The attacker controls which expression types are loaded into a rule. 4. TOCTOU race: __nf_tables_dump_rules() also calls nft_flow_rule_create() under rcu_read_lock() (the outer lock in nf_tables_dump_rules). If rule expressions are concurrently modified between the two walks, the count can diverge. 5. err_out path: On error, kfree(ctx) is called correctly, but nft_flow_rule_destroy(flow) is called — if flow->rule has already been partially written OOB and then freed, this creates a secondary corruption.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

The structural pattern (count with one predicate, execute with another) is real and present in the code at lines 57-62 vs 81-91. However, the vulnerability is only exploitable if an expression type has ->offload set but lacks NFT_OFFLOAD_F_ACTION while still writing action entries — a condition not demonstrated. Existing nftables expression implementations (nft_immediate, nft_fwd for actions; nft_meta, nft_payload for matches) follow the expected contract. The TOCTOU race is largely mitigated by nfnl_lock serialization of netlink operations. Without a concrete expression exhibiting the flag mismatch, this is a design observation, not a confirmed exploitable vulnerability.

**False-positive reason:** The alleged OOB write requires a specific expression type that (a) has a non-NULL ->offload callback, (b) does NOT set NFT_OFFLOAD_F_ACTION in offload_flags, yet (c) still writes to flow->rule->action.entries[] inside its ->offload callback. The primary agent has not identified any such expression in the kernel. The two-walk predicate asymmetry is real but by design: match expressions write to the match dissector, not action entries; action expressions set NFT_OFFLOAD_F_ACTION and write action entries. The system is internally consistent unless a specific expression misimplements this contract, which has not been demonstrated. The TOCTOU race claim is also weak because nf_tables netlink operations are serialized by nfnl_lock, and rule expression lists are immutable once committed.

## Remediation

If a specific expression is found to lack NFT_OFFLOAD_F_ACTION while writing action entries, add the flag to its offload_flags. Defensively, the second walk could also be restricted to expressions with NFT_OFFLOAD_F_ACTION for action-writing operations, or an index bounds check could be added before writing to action.entries[].

---
*Graph vulnerability score: 12.71 | Betweenness: 0.0000 | PageRank: 0.000405*
