# [INFORMATIONAL] Use After Free in nf_flow_offload_rule_alloc (CWE-416)

**Generated:** 2026-03-06T04:05:25.650723+00:00  
**Report ID:** `nf_flow_offload_rule_alloc_fc212e67`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_flow_table_offload.c` |
| Function | `nf_flow_offload_rule_alloc` |
| Line | 576 |
| Subsystem | net |

## Source Code

```c
  576 | nf_flow_offload_rule_alloc(struct net *net,
  577 | 			   const struct flow_offload_work *offload,
  578 | 			   enum flow_offload_tuple_dir dir)
  579 | {
  580 | 	const struct nf_flowtable *flowtable = offload->flowtable;
  581 | 	const struct flow_offload *flow = offload->flow;
  582 | 	const struct flow_offload_tuple *tuple;
  583 | 	struct nf_flow_rule *flow_rule;
  584 | 	struct dst_entry *other_dst;
  585 | 	int err = -ENOMEM;
  586 | 
  587 | 	flow_rule = kzalloc(sizeof(*flow_rule), GFP_KERNEL);
  588 | 	if (!flow_rule)
  589 | 		goto err_flow;
  590 | 
  591 | 	flow_rule->rule = flow_rule_alloc(NF_FLOW_RULE_ACTION_MAX);
  592 | 	if (!flow_rule->rule)
  593 | 		goto err_flow_rule;
  594 | 
  595 | 	flow_rule->rule->match.dissector = &flow_rule->match.dissector;
  596 | 	flow_rule->rule->match.mask = &flow_rule->match.mask;
  597 | 	flow_rule->rule->match.key = &flow_rule->match.key;
  598 | 
  599 | 	tuple = &flow->tuplehash[dir].tuple;
  600 | 	other_dst = flow->tuplehash[!dir].tuple.dst_cache;
  601 | 	err = nf_flow_rule_match(&flow_rule->match, tuple, other_dst);
  602 | 	if (err < 0)
  603 | 		goto err_flow_match;
  604 | 
  605 | 	flow_rule->rule->action.num_entries = 0;
  606 | 	if (flowtable->type->action(net, flow, dir, flow_rule) < 0)
  607 | 		goto err_flow_match;
  608 | 
  609 | 	return flow_rule;
  610 | 
  611 | err_flow_match:
  612 | 	kfree(flow_rule->rule);
  613 | err_flow_rule:
  614 | 	kfree(flow_rule);
  615 | err_flow:
  616 | 	return NULL;
  617 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-416 |
| Type | use_after_free |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

The function `nf_flow_offload_rule_alloc` is called from a deferred/workqueue context (`flow_offload_work_add`) and accesses `offload->flow` and `offload->flowtable` without holding any lock or refcount guarantee. Specifically at line 600: `other_dst = flow->tuplehash[!dir].tuple.dst_cache;` — the `dst_cache` pointer inside `flow_offload_tuple` is a `struct dst_entry *` that can be released/replaced concurrently (e.g., via route invalidation, `dst_release`, or `flow_offload_del`). The `flow_offload_work` structure is processed asynchronously in a workqueue; if the flow entry is deleted (NF_FLOW_HW_DYING set, flow torn down) between the time the work item was enqueued and when this function executes, `offload->flow` itself may be freed, making this a classic UAF on deferred work paths (P7). Additionally, `other_dst` is dereferenced inside `nf_flow_rule_match` (passed as argument at line 601) without a `dst_hold()` call to increment its refcount, meaning a concurrent `dst_release()` from a routing subsystem thread can free the dst_entry while `nf_flow_rule_match` is still reading from it. A secondary concern (P2): `flow_rule_alloc(NF_FLOW_RULE_ACTION_MAX)` at line 591 — the size of the action array depends on the macro value; if `NF_FLOW_RULE_ACTION_MAX` is user-influenced (via netlink-registered flowtable type), the allocation size could be miscalculated. The `flowtable->type->action` function pointer call at line 606 dereferences a function pointer from a kernel object whose type registration path should be audited for untrusted input. The critical UAF path: (1) `flow_offload_teardown()` is called from softirq/timer context setting NF_FLOW_HW_DYING; (2) the flow_offload_work is already queued; (3) before the workqueue executes, the flow is freed via `flow_offload_free()`; (4) `nf_flow_offload_rule_alloc` then dereferences `offload->flow` at line 581 and `flow->tuplehash[!dir].tuple.dst_cache` at line 600 — both are UAF reads. The `other_dst` pointer is then passed to `nf_flow_rule_match` and potentially dereferenced for tunnel info at the `ip_tunnel_info` path inside that function, constituting a UAF read of a freed dst_entry.

## Impact

Theoretical UAF read if lifecycle synchronization is absent; not demonstrated to be exploitable given standard kernel workqueue/dst refcount practices

## Attack Path

```
Userspace (nft/iptables via netlink) → nf_flowtable_type_register → flowtable hardware offload path → flow_offload_add → flow_offload_queue_work(NF_FLOW_OFFLOAD_ADD) → workqueue deferred execution → flow_offload_work_handler → flow_offload_work_add → nf_flow_offload_alloc → nf_flow_offload_rule_alloc [UAF on offload->flow and dst_cache at lines 581, 600, 601]
```

## Check-Bypass Analysis

1. No refcount is taken on `offload->flow` before the workqueue item is enqueued. The work item holds a pointer to the flow_offload structure but the flowtable teardown path (`nf_flow_table_cleanup`, `flow_offload_del`) can free this structure asynchronously. There is no RCU read lock held across lines 581-601, and no `flow_get`/`flow_put` refcounting visible in the caller `nf_flow_offload_alloc`. 2. `other_dst = flow->tuplehash[!dir].tuple.dst_cache` (line 600) reads a dst_entry pointer without calling `dst_hold()`. The routing subsystem can call `dst_release()` from an IRQ/softirq context (e.g., on neighbour update, PMTU change), freeing the dst_entry while the offload workqueue thread is mid-execution in `nf_flow_rule_match`. 3. The function pointer `flowtable->type->action` (line 606) is invoked without verifying the flowtable type is still valid — if the flowtable module is unregistered (via `nf_flowtable_type_unregister`) between enqueue and execution, this is a UAF function pointer dereference. 4. No `WARN_ON` or existence check is performed on `offload->flow` or `offload->flowtable` at entry to this function, meaning callers from the workqueue context provide no safety guarantees.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** MEDIUM

Primary agent notes absence of explicit locks/refcounts in nf_flow_offload_rule_alloc itself, but does not demonstrate that the calling infrastructure (flowtable teardown, work cancellation, dst_hold at tuple insertion time) fails to provide the required guarantees. The CVSS score exceeding 10.0 indicates a flawed scoring methodology. The attack path requires CAP_NET_ADMIN to register flowtable types. Without concrete evidence that flow_offload_free() races with workqueue execution (e.g., missing cancel_work_sync in teardown path), this remains speculative.

**False-positive reason:** The alleged UAF relies on `offload->flow` being freed while the workqueue item executes. In the actual kernel implementation, the flowtable teardown path synchronizes with pending work items (via cancel_work_sync or equivalent drain) before freeing flow entries, preventing the claimed race. The `dst_cache` pointer in `flow_offload_tuple` holds a dst reference (dst_hold was called when the dst was stored in the tuple), so concurrent dst_release from the routing subsystem does not free it while valid references exist. The primary agent's analysis does not provide concrete evidence that these synchronization guarantees are absent — it argues from absence of visible locks in this specific function, ignoring lifecycle management at the enqueue/teardown level. The vulnerability score of 12.7 (above CVSS maximum of 10.0) also indicates scoring methodology errors in the primary analysis. No concrete exploit path is demonstrated with specific evidence that the flow lifetime and dst refcount invariants are actually violated.

## Remediation

If a genuine race is confirmed via code audit of the teardown path showing missing synchronization, add explicit refcounting on flow_offload structures accessed from workqueue context, and ensure dst_hold() is called when reading dst_cache outside of RCU/lock protection.

---
*Graph vulnerability score: 12.67 | Betweenness: 0.0000 | PageRank: 0.000573*
