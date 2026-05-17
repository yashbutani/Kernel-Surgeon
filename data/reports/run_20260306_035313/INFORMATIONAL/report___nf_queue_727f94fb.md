# [INFORMATIONAL] Use After Free in __nf_queue (CWE-362)

**Generated:** 2026-03-06T03:55:46.283222+00:00  
**Report ID:** `__nf_queue_727f94fb`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_queue.c` |
| Function | `__nf_queue` |
| Line | 155 |
| Subsystem | net |

## Source Code

```c
  155 | static int __nf_queue(struct sk_buff *skb, const struct nf_hook_state *state,
  156 | 		      unsigned int index, unsigned int queuenum)
  157 | {
  158 | 	struct nf_queue_entry *entry = NULL;
  159 | 	const struct nf_queue_handler *qh;
  160 | 	struct net *net = state->net;
  161 | 	unsigned int route_key_size;
  162 | 	int status;
  163 | 
  164 | 	/* QUEUE == DROP if no one is waiting, to be safe. */
  165 | 	qh = rcu_dereference(net->nf.queue_handler);
  166 | 	if (!qh)
  167 | 		return -ESRCH;
  168 | 
  169 | 	switch (state->pf) {
  170 | 	case AF_INET:
  171 | 		route_key_size = sizeof(struct ip_rt_info);
  172 | 		break;
  173 | 	case AF_INET6:
  174 | 		route_key_size = sizeof(struct ip6_rt_info);
  175 | 		break;
  176 | 	default:
  177 | 		route_key_size = 0;
  178 | 		break;
  179 | 	}
  180 | 
  181 | 	entry = kmalloc(sizeof(*entry) + route_key_size, GFP_ATOMIC);
  182 | 	if (!entry)
  183 | 		return -ENOMEM;
  184 | 
  185 | 	if (skb_dst(skb) && !skb_dst_force(skb)) {
  186 | 		kfree(entry);
  187 | 		return -ENETDOWN;
  188 | 	}
  189 | 
  190 | 	*entry = (struct nf_queue_entry) {
  191 | 		.skb	= skb,
  192 | 		.state	= *state,
  193 | 		.hook_index = index,
  194 | 		.size	= sizeof(*entry) + route_key_size,
  195 | 	};
  196 | 
  197 | 	__nf_queue_entry_init_physdevs(entry);
  198 | 
  199 | 	nf_queue_entry_get_refs(entry);
  200 | 
  201 | 	switch (entry->state.pf) {
  202 | 	case AF_INET:
  203 | 		nf_ip_saveroute(skb, entry);
  204 | 		break;
  205 | 	case AF_INET6:
  206 | 		nf_ip6_saveroute(skb, entry);
  207 | 		break;
  208 | 	}
  209 | 
  210 | 	status = qh->outfn(entry, queuenum);
  211 | 	if (status < 0) {
  212 | 		nf_queue_entry_free(entry);
  213 | 		return status;
  214 | 	}
  215 | 
  216 | 	return 0;
  217 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-362 |
| Type | use_after_free |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

The function `__nf_queue` contains a UAF vulnerability at line 210 (`qh->outfn(entry, queuenum)`) via an RCU read-side critical section violation. The `queue_handler` is dereferenced via `rcu_dereference()` at line 165, which is correct only if the caller holds the RCU read lock. However, between lines 165 and 210, the code performs memory allocations (`kmalloc` at line 181), conditional frees (`kfree` at line 186), and multiple function calls (`__nf_queue_entry_init_physdevs`, `nf_queue_entry_get_refs`, `nf_ip_saveroute`/`nf_ip6_saveroute`). If `GFP_ATOMIC` allocation path is safe in terms of RCU (it should be), the primary concern is whether the RCU read lock is held across the entire function body covering the `qh->outfn()` call.

A secondary and more concrete vulnerability path exists through `nf_reinject()` → `__nf_queue()`: `nf_reinject` re-queues a packet that was previously dequeued. The `entry` passed into `nf_reinject` was previously owned by the queue handler (e.g., nfnetlink_queue). After `nf_queue_entry_free()` is called on error at line 212, the `entry` is freed. However, the `qh->outfn()` callback (e.g., `nfqnl_enqueue_packet`) may asynchronously reference the entry after `outfn` returns a success code and the userspace nfnetlink handler concurrently sends a verdict — triggering `nf_reinject`, which then calls `__nf_queue` again with the same `entry`, whose `skb` may already be in a freed/reused state.

The most critical concrete issue: at line 199, `nf_queue_entry_get_refs(entry)` increments refcounts on `state->in`, `state->out`, and `state->sk`. At line 212, `nf_queue_entry_free(entry)` decrements those same refcounts and frees entry. If `qh->outfn()` (line 210) takes ownership of `entry` (as nfnetlink_queue does — it stores entry in a per-socket list), and `outfn` returns 0 (success), but a race window exists where the queue socket is destroyed concurrently, the stored `entry` pointer is accessed after the nfnetlink socket teardown frees its pending entries. The caller `nf_reinject` holds `entry` by raw pointer with no refcount on the entry itself — only on nested objects. This is a classic UAF pattern where the entry lifecycle is not protected by a reference count on the entry structure itself.

Additionally: the `qh` pointer retrieved at line 165 via `rcu_dereference` — if the RCU read lock is NOT held by the caller chain (nf_hook_slow does hold it, but nf_reinject's path to __nf_queue needs verification), then `qh` could be freed between the dereference and the `qh->outfn()` call at line 210, constituting a UAF on the queue_handler itself.

## Impact

No demonstrated impact; the alleged UAF scenarios are speculative and contradicted by the actual code logic showing correct entry ownership transfer semantics and standard RCU usage patterns

## Attack Path

```
Userspace (NFQUEUE) → nfnetlink verdict → nf_reinject(entry) → __nf_queue(skb, state, index, queuenum) → qh->outfn(entry, queuenum) [line 210] — entry UAF if concurrent socket destruction races with reinject path; OR: nf_hook_slow → nf_queue → __nf_queue → qh->outfn where qh freed after rcu_dereference if read lock not maintained
```

## Check-Bypass Analysis

1. The `nf_reinject` caller does NOT appear to hold the RCU read lock across the call to `__nf_queue`. `nf_reinject` calls `nf_hook_entries_head` which uses `rcu_dereference` internally, but the critical question is whether `rcu_read_lock()` is held for the entire duration including the `qh->outfn()` call at line 210. If rcu_read_lock is dropped before outfn, the qh pointer is invalid.
2. The `entry` structure has no refcount of its own. After `qh->outfn(entry, 0)` succeeds and the entry is handed to nfnetlink_queue's pending list, a concurrent `nfqnl_flush()` or socket close can free the entry. Meanwhile `nf_reinject` holds a raw pointer to this same entry.
3. `nf_queue_entry_get_refs` at line 199 increments netdev/sock refcounts but does NOT increment a refcount on the entry itself, leaving the entry's lifetime unprotected against concurrent freeing by the queue handler.
4. The `nf_queue` caller (line 220-233) passes `verdict >> NF_VERDICT_QBITS` as queuenum — the upper bits of the verdict word. If the verdict value is attacker-controlled (via userspace nfnetlink NF_VERDICT_QUEUE), the queuenum could route to arbitrary queue numbers, but this is bounded by nfnetlink's queue lookup logic.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Entry lifecycle: allocated at L181, initialized L190-197, refs taken L199, passed to outfn L210. On success (status>=0): function returns 0 without freeing — ownership correctly transferred to queue handler. On failure (status<0): nf_queue_entry_free called — correct cleanup since outfn did not take ownership. RCU: rcu_dereference at L165 is valid because all callers (nf_hook_slow via packet processing, nf_reinject) hold rcu_read_lock for the duration. The primary agent's assertion that rcu_read_lock may not be held is not backed by any code reference showing a call path that bypasses rcu_read_lock acquisition. CAP_NET_ADMIN required for NFQUEUE use, further limiting attack surface.

**False-positive reason:** The alleged UAF scenarios are not supported by the code evidence. (1) RCU read lock IS held by all callers in the netfilter framework (nf_hook_slow and nf_reinject both acquire rcu_read_lock before reaching __nf_queue); the agent's claim to the contrary is unsubstantiated. (2) Entry ownership is correctly transferred to outfn on success — __nf_queue does NOT free the entry after outfn returns 0, so there is no double-free or UAF in that path. (3) The 'nf_reinject holds raw pointer to same entry while outfn processes it' claim is logically inconsistent with the code: nf_reinject creates a new queue operation context; the original entry is not shared. (4) The error-path free at line 212 is called only when outfn returns negative, at which point outfn has not taken ownership, so nf_queue_entry_free is the correct and safe cleanup. No concrete UAF exists in the provided code.

## Remediation

No fix required for the alleged vulnerabilities as they are not real. Standard code review for the netfilter queue path should continue to verify RCU discipline and entry ownership invariants are maintained as the code evolves.

---
*Graph vulnerability score: 12.88 | Betweenness: 0.0000 | PageRank: 0.000708*
